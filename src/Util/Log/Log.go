package Log

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
)

// Init keeps human diagnostics on stderr, leaving stdout for runtime JSON.
// Disk logs in ./logs are optional; an unwritable cwd does not block startup.
// The caller must close the returned disk-log lifetime after app cleanup.
func Init() func() {
	mode := os.Getenv("LOG_MODE")
	if mode == "" {
		mode = "production"
	}
	var closeLog func()
	var err error

	switch mode {
	case "production":
		closeLog, err = initLog(PRODUCTION_MODE)
	case "development":
		closeLog, err = initLog(DEVELOPMENT_MODE)
	default:
		closeLog, err = initLog(PRODUCTION_MODE)
		Warn.Printf("Invalid logging mode: %s, set log level for production", mode)
	}
	if err != nil {
		Warn.Println("Host disk logs unavailable; continuing with stderr logging.")
	}
	return closeLog
}

var (
	PRODUCTION_MODE  = 3
	DEVELOPMENT_MODE = 4
)

var (
	Verbose *log.Logger
	Warn    *log.Logger
	Info    *log.Logger
	Error   *log.Logger
)

func initLog(level int) (func(), error) {
	closeLog := func() {}
	Verbose = log.New(io.Discard, "[DEBG] ", log.Ldate|log.Ltime|log.Lshortfile)
	Info = log.New(os.Stderr, "[INFO] ", log.Ldate|log.Ltime|log.Lshortfile)
	Warn = log.New(os.Stderr, "[WARN] ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(os.Stderr, "[ERR!] ", log.Ldate|log.Ltime|log.Lshortfile)

	date := time.Now().Format("2006-01-02_150405")
	pwd, err := os.Getwd()
	if err != nil {
		return closeLog, err
	}

	FolderPath := filepath.Join(pwd, "logs")
	FilePath := filepath.Join(pwd, "logs", date+".log")

	if err := os.MkdirAll(FolderPath, os.ModePerm); err != nil {
		return closeLog, err
	}

	LogFile, err := os.OpenFile(FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return closeLog, err
	}

	Writer := io.MultiWriter(os.Stderr, LogFile)

	if level < 1 {
		panic("Invaild logging mode. (1, 2, 3, 4)")
	}

	if level >= 1 {
		Error = log.New(os.Stderr, color.HiRedString("[ERR!] "), log.Ldate|log.Ltime)
		Error.SetOutput(Writer)
	}

	if level >= 2 {
		Warn = log.New(os.Stderr, color.YellowString("[WARN] "), log.Ldate|log.Ltime)
		Warn.SetOutput(Writer)
	}

	if level >= 3 {
		Info = log.New(os.Stderr, color.CyanString("[INFO] "), log.Ldate|log.Ltime)
		Info.SetOutput(Writer)
	}

	if level >= 4 {
		Verbose = log.New(os.Stderr, "[DEBG] ", log.Ldate|log.Ltime|log.Lshortfile)
		Info.Println("Verbose logging is enabled. Only use this mode for debugging.")
		Verbose.SetOutput(Writer)
	}

	if level > 4 {
		Warn.Println("Logging mode is greater than 4. Logging mode is set to the maximum level.")
	}

	return func() { _ = LogFile.Close() }, nil
}
