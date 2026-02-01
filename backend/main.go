package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"zmscan/backend/api"
	"zmscan/backend/poc"
	"zmscan/backend/scanner"
)

const (
	Version = "1.0.0"
	Name    = "zmscan"
)

func main() {
	// 命令行参数
	port := flag.Int("port", 8080, "API服务器端口")
	pocsDir := flag.String("pocs", "../pocs", "POC目录路径")
	maxWorkers := flag.Int("workers", 50, "最大扫描并发数")
	timeout := flag.Int("timeout", 10, "默认超时时间(秒)")
	showVersion := flag.Bool("version", false, "显示版本信息")

	flag.Parse()

	// 显示版本
	if *showVersion {
		fmt.Printf("%s v%s\n", Name, Version)
		return
	}

	// 初始化POC管理器
	log.Println("正在初始化POC管理器...")
	pocManager := poc.NewPOCManager()

	// 确保POC目录存在
	if err := ensureDir(*pocsDir); err != nil {
		log.Fatalf("创建POC目录失败: %v", err)
	}

	// 确保子目录存在
	for _, cat := range pocManager.GetCategories() {
		catDir := filepath.Join(*pocsDir, cat)
		if err := ensureDir(catDir); err != nil {
			log.Printf("警告: 创建目录 %s 失败: %v", catDir, err)
		}
	}

	// 加载POC
	if err := pocManager.LoadFromDir(*pocsDir); err != nil {
		log.Fatalf("加载POC失败: %v", err)
	}

	log.Printf("成功加载 %d 个POC", pocManager.GetPOCCount())

	// 打印分类统计
	for _, cat := range pocManager.GetCategories() {
		count := pocManager.GetPOCCountByCategory(cat)
		if count > 0 {
			log.Printf("  - %s: %d 个", cat, count)
		}
	}

	// 初始化扫描器
	log.Println("正在初始化扫描器...")
	scanEngine := scanner.NewScanner(
		pocManager,
		scanner.WithMaxWorkers(*maxWorkers),
		scanner.WithTimeout(time.Duration(*timeout)*time.Second),
	)

	// 初始化API服务器
	log.Println("正在初始化API服务器...")
	apiServer := api.NewServer(pocManager, scanEngine, *port)

	// 设置信号处理
	go handleSignals(apiServer)

	// 启动服务器
	log.Printf("%s v%s 启动成功", Name, Version)
	log.Printf("API服务器监听: http://localhost:%d", *port)
	log.Printf("POC目录: %s", *pocsDir)

	if err := apiServer.Start(); err != nil {
		log.Fatalf("启动服务器失败: %v", err)
	}
}

// ensureDir 确保目录存在
func ensureDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0755)
	}
	return nil
}

// handleSignals 处理系统信号
func handleSignals(server *api.Server) {
	// 这里可以添加信号处理逻辑
	// 例如: Ctrl+C 时优雅关闭
}
