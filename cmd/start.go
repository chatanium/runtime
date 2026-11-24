	"os"
	"os/signal"
	"syscall"
	"github.com/thirdscam/chatanium/internal/app"
	"github.com/thirdscam/chatanium/src/Util"
	"github.com/thirdscam/chatanium/src/Util/Log"
var startOptions app.StartOptions
		if !startOptions.DevelopmentMode && (cmd.Flags().Changed("dev-socket") || cmd.Flags().Changed("dev-module-image")) {
		if err := Util.InitEnv(); err != nil {
		closeLog := Log.Init()
		defer closeLog()
		Log.Info.Println("Antegral/Chatanium: Dynamic Bot Management System")
		Log.Info.Println("Press CTRL+C to shutdown.")
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return app.Start(ctx, startOptions)
	flags.StringVar(&startOptions.ConfigPath, "config", "", "absolute operator JSON configuration")
	flags.StringVar(&startOptions.SupervisorSocket, "supervisor-socket", "", "absolute independently supervised host socket")
	flags.Int64Var(&startOptions.SupervisorUID, "supervisor-uid", -1, "trusted supervisor UID")
	flags.IntVar(&startOptions.SupervisorMaxBytes, "supervisor-max-bytes", 0, "supervisor packet bound")