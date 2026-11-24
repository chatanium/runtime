	"github.com/thirdscam/chatanium/internal/app"
var generateConfigOptions app.GenerateConfigOptions
		return app.GenerateConfig(cmd.Context(), generateConfigOptions)
	flags.StringVar(&generateConfigOptions.Base, "base", "", "absolute host configuration with modules:[]")
	flags.StringVar(&generateConfigOptions.Image, "image", "", "real immutable registry/repository@sha256 digest")
	flags.StringVar(&generateConfigOptions.ModuleID, "module-id", "", "stable operator-assigned module ID")
	flags.StringVar(&generateConfigOptions.Entrypoint, "entrypoint", "", "approved image executable absolute path")
	flags.StringVar(&generateConfigOptions.ConfigRevision, "config-revision", "", "operator configuration revision")
	flags.StringVar(&generateConfigOptions.ApprovalRevision, "approval-revision", "", "operator approval revision")
	flags.StringVar(&generateConfigOptions.SupervisorSocket, "supervisor-socket", "", "absolute real supervisor socket for image verification")
	flags.Int64Var(&generateConfigOptions.SupervisorUID, "supervisor-uid", -1, "trusted supervisor UID")
	flags.IntVar(&generateConfigOptions.SupervisorMaxBytes, "supervisor-max-bytes", 0, "supervisor packet bound")