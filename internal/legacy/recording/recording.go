package recording

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

// Handle attaches trusted host recording to the existing backend session before
// its Gateway opens. The returned stop detaches, cancels and joins all callbacks
// before the caller closes the database. It is safe to call stop more than once.
func Handle(parent context.Context, client *discordgo.Session, db *DB, deadline time.Duration, maxResponseBytes int64, onError func(error)) func() {
	ctx, cancel := context.WithCancel(parent)
	var mu, serial sync.Mutex
	var active sync.WaitGroup
	closed := false
	run := func(operation func(context.Context) error) {
		mu.Lock()
		if closed {
			mu.Unlock()
			return
		}
		active.Add(1)
		mu.Unlock()
		defer active.Done()
		bounded, done := context.WithTimeout(ctx, deadline)
		defer done()
		// User/member existence checks and inserts must not race on callbacks.
		serial.Lock()
		defer serial.Unlock()
		if bounded.Err() != nil {
			return
		}
		if err := operation(bounded); err != nil && bounded.Err() == nil && onError != nil {
			onError(errors.New("host Discord recording failed"))
		}
	}
	remove := []func(){
		client.AddHandler(func(s *discordgo.Session, event *discordgo.GuildCreate) {
			if event == nil || event.Guild == nil {
				return
			}
			run(func(ctx context.Context) error {
				return registerGuild(ctx, s, db.Conn, db.Queries, event.Guild, maxResponseBytes)
			})
		}),
		client.AddHandler(func(_ *discordgo.Session, event *discordgo.MessageCreate) {
			run(func(ctx context.Context) error { return createMessage(ctx, event, db.Queries) })
		}),
		client.AddHandler(func(_ *discordgo.Session, event *discordgo.MessageDelete) {
			run(func(ctx context.Context) error { return deleteMessage(ctx, event, db.Queries) })
		}),
	}
	// MessageUpdate was never persisted by the old host; do not fabricate an
	// update operation or dereference missing author/member fields on partials.
	var once sync.Once
	return func() {
		once.Do(func() {
			mu.Lock()
			closed = true
			cancel()
			mu.Unlock()
			for _, detach := range remove {
				detach()
			}
			active.Wait()
		})
	}
}
