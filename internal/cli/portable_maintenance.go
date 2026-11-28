package cli

import (
	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/portable/install"
)

func init() {
	bind := installedCommand("bind-restored-volumes", "Verify a sealed portable backup and bind its restored volumes", func(cmd *cobra.Command, path string) error {
		backupID, _ := cmd.Flags().GetString("backup-id")
		receiptDigest, _ := cmd.Flags().GetString("receipt-digest")
		if err := install.BindRestoredVolumes(cmd.Context(), path, backupID, receiptDigest); err != nil {
			return err
		}
		return operatorResult(cmd, "Restored volumes verified and bound.", map[string]string{"state": "RESTORED", "backup_id": backupID, "receipt_digest": receiptDigest})
	})
	bind.Flags().String("backup-id", "", "ID of the sealed portable backup")
	bind.Flags().String("receipt-digest", "", "trusted SHA-256 of the backup's exact inventory.json bytes (sha256:...)")
	jsonOutputFlag(bind)
	addOperatorCommands("maintenance", bind)
}

func addMaintenanceCommands() {
	update := installedCommand("update", "Approve a stopped backup and compatible portable binary update", func(cmd *cobra.Command, path string) error {
		m, err := install.Update(cmd.Context(), path, approval(cmd))
		return manifestResult(cmd, m, err)
	})
	approvalFlag(update)
	uninstall := installedCommand("uninstall", "Remove only installed portable code, retaining data", func(cmd *cobra.Command, path string) error {
		m, err := install.Uninstall(cmd.Context(), path)
		return manifestResult(cmd, m, err)
	})
	purge := installedCommand("purge", "Approve permanent deletion of this portable installation", func(cmd *cobra.Command, path string) error {
		if err := install.Purge(cmd.Context(), path, approval(cmd)); err != nil {
			return err
		}
		return operatorResult(cmd, "Installation and managed data deleted.", map[string]string{"state": "PURGED"})
	})
	approvalFlag(purge)
	for _, command := range []*cobra.Command{update, uninstall, purge} {
		jsonOutputFlag(command)
	}
	addOperatorCommands("maintenance", update, uninstall, purge)
}
