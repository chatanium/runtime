// Package voicejobs implements the optional owner-bound Discord voice service.
// It does not import the parent backend or enable native voice in ordinary builds.
package voicejobs

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config has no resource defaults. Every bound must be supplied explicitly.
// Frame/byte budgets include unused credits and the single sender-owned frame.
// Message budgets reserve one inbound and outbound gRPC message per RPC. A job's
// status reservation covers its mailbox and immutable current queue-query view.
// The SDK transport's separately bounded socket/control/native buffers are also
// explicit, and exist at most HostSessions times; they are not subscription queues.
type Config struct {
	Transport             discordgo.VoiceConfig `json:"transport"`
	HostSessions          int                   `json:"host_sessions"`
	InstanceSessions      int                   `json:"instance_sessions"`
	GuildJobs             int                   `json:"guild_jobs"`
	InstanceJobs          int                   `json:"instance_jobs"`
	HostJobs              int                   `json:"host_jobs"`
	WaitingJobs           int                   `json:"waiting_jobs"`
	JobFrames             int                   `json:"job_frames"`
	InstanceFrames        int                   `json:"instance_frames"`
	HostFrames            int                   `json:"host_frames"`
	JobBytes              int64                 `json:"job_bytes"`
	InstanceBytes         int64                 `json:"instance_bytes"`
	HostBytes             int64                 `json:"host_bytes"`
	InitialCreditFrames   int                   `json:"initial_credit_frames"`
	MaxOpusPacketBytes    int                   `json:"max_opus_packet_bytes"`
	MaxGRPCMessageBytes   int                   `json:"max_grpc_message_bytes"`
	InstanceMessageBytes  int64                 `json:"instance_message_bytes"`
	HostMessageBytes      int64                 `json:"host_message_bytes"`
	JobLifetime           time.Duration         `json:"job_lifetime"`
	FirstBindTimeout      time.Duration         `json:"first_bind_timeout"`
	InputIdleTimeout      time.Duration         `json:"input_idle_timeout"`
	ConnectionTimeout     time.Duration         `json:"connection_timeout"`
	SubmissionTimeout     time.Duration         `json:"submission_timeout"`
	ReceiptTimeout        time.Duration         `json:"receipt_timeout"`
	CleanupTimeout        time.Duration         `json:"cleanup_timeout"`
	InstanceSubscriptions int                   `json:"instance_subscriptions"`
	GuildSubscriptions    int                   `json:"guild_subscriptions"`
	HostSubscriptions     int                   `json:"host_subscriptions"`
	SubscriptionLifetime  time.Duration         `json:"subscription_lifetime"`
	SubscriptionPackets   int                   `json:"subscription_packets"`
	HostReceivePackets    int                   `json:"host_receive_packets"`
	SubscriptionBytes     int64                 `json:"subscription_bytes"`
	HostReceiveBytes      int64                 `json:"host_receive_bytes"`
	SlowConsumerTimeout   time.Duration         `json:"slow_consumer_timeout"`
	MaxSSRCFilters        int                   `json:"max_ssrc_filters"`
	StatusMailbox         int                   `json:"status_mailbox"`
	ControlMailbox        int                   `json:"control_mailbox"`
	StatusMailboxBytes    int64                 `json:"status_mailbox_bytes"`
	HostStatusBytes       int64                 `json:"host_status_bytes"`
	TerminalRecords       int                   `json:"terminal_records"`
	TerminalTTL           time.Duration         `json:"terminal_ttl"`
	QueuePageSize         int                   `json:"queue_page_size"`
	RelationshipTimeout   time.Duration         `json:"relationship_timeout"`
}

func (c Config) Validate() error {
	v := reflect.ValueOf(c)
	t := v.Type()
	for n := range v.NumField() {
		if t.Field(n).Name == "Transport" {
			continue
		}
		if v.Field(n).Int() <= 0 {
			return fmt.Errorf("voicejobs: %s must be finite and positive", t.Field(n).Name)
		}
	}
	if c.MaxGRPCMessageBytes > math.MaxInt32 || c.MaxOpusPacketBytes > c.MaxGRPCMessageBytes || c.MaxOpusPacketBytes != c.Transport.MaxOpusBytes || c.InitialCreditFrames > c.JobFrames || c.JobFrames > c.InstanceFrames || c.InstanceFrames > c.HostFrames || c.JobBytes > c.InstanceBytes || c.InstanceBytes > c.HostBytes || c.InstanceSessions > c.HostSessions || c.InstanceJobs > c.HostJobs || c.GuildJobs > c.HostJobs || c.SubscriptionPackets > c.HostReceivePackets || c.SubscriptionBytes > c.HostReceiveBytes || c.InstanceSubscriptions > c.HostSubscriptions || c.GuildSubscriptions > c.HostSubscriptions || c.QueuePageSize > c.HostJobs && c.QueuePageSize-c.HostJobs > c.TerminalRecords {
		return fmt.Errorf("voicejobs: contradictory bounds")
	}
	if 2*int64(c.MaxGRPCMessageBytes) > c.InstanceMessageBytes || c.InstanceMessageBytes > c.HostMessageBytes || c.StatusMailbox == math.MaxInt || int64(c.StatusMailbox+1) > math.MaxInt64/int64(c.MaxGRPCMessageBytes) || int64(c.StatusMailbox+1)*int64(c.MaxGRPCMessageBytes) > c.StatusMailboxBytes || c.StatusMailboxBytes > c.HostStatusBytes {
		return fmt.Errorf("voicejobs: contradictory message bounds")
	}
	if int64(c.InitialCreditFrames) > math.MaxInt64/int64(c.MaxOpusPacketBytes) || int64(c.InitialCreditFrames)*int64(c.MaxOpusPacketBytes) > c.JobBytes || c.SubscriptionPackets > math.MaxInt-2 || maxVoiceMessageBytes(c.MaxOpusPacketBytes) > int64(c.MaxGRPCMessageBytes) {
		return fmt.Errorf("voicejobs: packet/window bounds do not fit")
	}
	if c.SubmissionTimeout > c.CleanupTimeout/2 || c.ReceiptTimeout > c.CleanupTimeout-2*c.SubmissionTimeout || c.Transport.CloseTimeout > (c.CleanupTimeout-2*c.SubmissionTimeout-c.ReceiptTimeout)/2 {
		return fmt.Errorf("voicejobs: cleanup deadline cannot contain sender, local abort and disconnect deadlines")
	}
	return c.Transport.Validate()
}

// Compute framing overhead without allocating an operator-sized packet. The
// 48-character IDs are exactly opaque()'s 24-byte hex encoding; snowflakes are
// bounded to 20 decimal digits at admission. This is wire arithmetic, not a quota
// default or an assumption that gRPC flow control replaces application budgets.
func maxVoiceMessageBytes(opusBytes int) int64 {
	id := strings.Repeat("f", 48)
	snowflake := strings.Repeat("9", 20)
	timestamp := &timestamppb.Timestamp{Seconds: -1, Nanos: 999999999}
	message := ""
	for _, name := range wire.VoiceErrorReason_name {
		if len(name) > len(message) {
			message = name
		}
	}
	detail := &wire.VoiceError{GrpcCode: 16, Reason: wire.VoiceErrorReason_VOICE_ERROR_REASON_DISCORD_PERMISSION_DENIED, Stage: wire.VoiceFailureStage_VOICE_FAILURE_STAGE_CLEANUP, Message: message, GuildId: snowflake, ChannelId: snowflake, JobId: id, SubscriptionId: id, MayHaveSubmitted: true}
	snapshot := &wire.PlaybackSnapshot{JobId: id, GuildId: snowflake, ChannelId: snowflake, Priority: math.MinInt32, State: wire.PlaybackState_PLAYBACK_STATE_FAILED, Reason: wire.PlaybackReason_PLAYBACK_REASON_WAITING_DAVE, LastAcceptedSequence: math.MaxUint64, LastSubmittedSequence: math.MaxUint64, LastUdpWrittenSequence: math.MaxUint64, InputEnded: true, FinalSequence: math.MaxUint64, CreditThroughSequence: math.MaxUint64, CreditThroughBytes: math.MaxUint64, ExpiresAt: timestamp, TerminalError: detail}
	maxBytes := int64(proto.Size(snapshot))
	bytesField := func(n int64) int64 { return int64(protowire.SizeVarint(uint64(n))) + n }
	packet := &wire.VoicePacket{SubscriptionId: id, Ssrc: math.MaxUint32, RtpSequence: math.MaxUint16, RtpTimestamp: math.MaxUint32, ReceiveSequence: math.MaxUint64, ReceivedAt: timestamp}
	packetBody := int64(proto.Size(packet)) + int64(protowire.SizeTag(7)) + bytesField(int64(opusBytes))
	packetEvent := int64(protowire.SizeTag(2)) + bytesField(packetBody)
	frameBody := int64(protowire.SizeTag(1)+protowire.SizeVarint(math.MaxUint64)+protowire.SizeTag(2)) + bytesField(int64(opusBytes))
	frameInput := int64(protowire.SizeTag(2)) + bytesField(frameBody)
	if packetEvent > maxBytes {
		maxBytes = packetEvent
	}
	if frameInput > maxBytes {
		maxBytes = frameInput
	}
	return maxBytes
}
