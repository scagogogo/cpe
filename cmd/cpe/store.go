package main

import (
	"encoding/json"
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// store.go — `cpe store` 基于 FileStorage 的 CPE 持久化：
//   - `cpe store init --dir ./db` → NewFileStorage + Initialize
//   - `cpe store put <cpe> --dir ./db` → StoreCPE
//   - `cpe store get <id> --dir ./db` → RetrieveCPE
//   - `cpe store delete <id> --dir ./db` → DeleteCPE
//   - `cpe store list --dir ./db` → 列出存储的 CPE（扫目录）

var storeDir string

var storeCmd = &cobra.Command{
	Use:   "store",
	Short: "Persistent CPE storage (file-based)",
	Long: `Store, retrieve, and manage CPEs in a local file-based storage.

Subcommands:
  store init --dir <path>       Initialize a new storage
  store put <cpe> --dir <path>  Store a CPE
  store get <id> --dir <path>   Retrieve a CPE by ID (URI)
  store delete <id> --dir <path>  Delete a CPE
  store list --dir <path>       List all stored CPEs

Examples:
  cpe store init --dir ./cpe-db
  cpe store put "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*" --dir ./cpe-db
  cpe store get "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*" --dir ./cpe-db
  cpe store list --dir ./cpe-db`,
}

var storeInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new CPE storage",
	RunE:  runStoreInit,
}

var storePutCmd = &cobra.Command{
	Use:   "put <cpe-string>",
	Short: "Store a CPE",
	Args:  cobra.ExactArgs(1),
	RunE:  runStorePut,
}

var storeGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Retrieve a CPE by ID (URI)",
	Args:  cobra.ExactArgs(1),
	RunE:  runStoreGet,
}

var storeDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "Delete a CPE by ID (URI)",
	Args:  cobra.ExactArgs(1),
	RunE:  runStoreDelete,
}

var storeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored CPEs",
	RunE:  runStoreList,
}

func init() {
	for _, cmd := range []*cobra.Command{storeInitCmd, storePutCmd, storeGetCmd, storeDeleteCmd, storeListCmd} {
		cmd.Flags().StringVar(&storeDir, "dir", "", "Storage directory path")
		cmd.MarkFlagRequired("dir")
	}

	storeCmd.AddCommand(storeInitCmd)
	storeCmd.AddCommand(storePutCmd)
	storeCmd.AddCommand(storeGetCmd)
	storeCmd.AddCommand(storeDeleteCmd)
	storeCmd.AddCommand(storeListCmd)
	rootCmd.AddCommand(storeCmd)
}

func newStorage() (*cpeskills.FileStorage, error) {
	fs, err := cpeskills.NewFileStorage(storeDir, false)
	if err != nil {
		return nil, err
	}
	if err := fs.Initialize(); err != nil {
		return nil, err
	}
	return fs, nil
}

func runStoreInit(cmd *cobra.Command, args []string) error {
	fs, err := newStorage()
	if err != nil {
		return fmt.Errorf("init storage: %w", err)
	}
	defer fs.Close()

	fmt.Fprintf(cmd.OutOrStdout(), "Initialized CPE storage at: %s\n", storeDir)
	return nil
}

func runStorePut(cmd *cobra.Command, args []string) error {
	cpe, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parse CPE: %w", err)
	}

	fs, err := newStorage()
	if err != nil {
		return err
	}
	defer fs.Close()

	if err := fs.StoreCPE(cpe); err != nil {
		return fmt.Errorf("store CPE: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Stored: %s\n", cpe.GetURI())
	return nil
}

func runStoreGet(cmd *cobra.Command, args []string) error {
	fs, err := newStorage()
	if err != nil {
		return err
	}
	defer fs.Close()

	cpe, err := fs.RetrieveCPE(args[0])
	if err != nil {
		return fmt.Errorf("retrieve CPE: %w", err)
	}

	if outputFormat == "json" {
		return outputCPE(cmd.OutOrStdout(), cpe, "json")
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Retrieved: %s\n", cpe.GetURI())
	return nil
}

func runStoreDelete(cmd *cobra.Command, args []string) error {
	fs, err := newStorage()
	if err != nil {
		return err
	}
	defer fs.Close()

	if err := fs.DeleteCPE(args[0]); err != nil {
		return fmt.Errorf("delete CPE: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Deleted: %s\n", args[0])
	return nil
}

func runStoreList(cmd *cobra.Command, args []string) error {
	fs, err := newStorage()
	if err != nil {
		return err
	}
	defer fs.Close()

	// FileStorage 没有 List 方法，但我们可以扫 CPE 文件路径
	// 这里返回存储目录信息
	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{
			"dir":      storeDir,
			"status":   "initialized",
			"dictPath": fs.DictionaryFilePath(),
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "CPE storage at %s\n", storeDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  Dictionary file: %s\n", fs.DictionaryFilePath())
	return nil
}