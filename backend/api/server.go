package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"zmscan/backend/poc"
	"zmscan/backend/scanner"
)

// Server API服务器
type Server struct {
	pocManager *poc.POCManager
	scanner    *scanner.Scanner
	server     *http.Server
	scanCtx     context.Context
	scanCancel  context.CancelFunc
	scanResult  *ScanSession
	scanMu      sync.RWMutex
}

// ScanSession 扫描会话
type ScanSession struct {
	ID         string                 `json:"id"`
	Status     string                 `json:"status"` // running, completed, stopped
	Results    []*poc.ScanResult      `json:"results"`
	Progress   *scanner.Progress       `json:"progress"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time"`
	TargetList []string               `json:"target_list"`
	POCID      string                 `json:"poc_id"`
	Category   string                 `json:"category"`
	MaxWorkers int                    `json:"max_workers"`
	Timeout    int                    `json:"timeout"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// NewServer 创建API服务器
func NewServer(pocManager *poc.POCManager, scanEngine *scanner.Scanner, port int) *Server {
	s := &Server{
		pocManager: pocManager,
		scanner:    scanEngine,
		scanResult: &ScanSession{},
	}

	// 创建路由
	mux := http.NewServeMux()

	// POC管理接口
	mux.HandleFunc("/api/pocs", s.handlePOCs)
	mux.HandleFunc("/api/pocs/", s.handlePOCByID)
	mux.HandleFunc("/api/pocs/upload", s.handlePOCUpload)
	mux.HandleFunc("/api/pocs/export", s.handlePOCExport)

	// 扫描接口
	mux.HandleFunc("/api/scan/start", s.handleScanStart)
	mux.HandleFunc("/api/scan/stop", s.handleScanStop)
	mux.HandleFunc("/api/scan/status", s.handleScanStatus)
	mux.HandleFunc("/api/scan/results", s.handleScanResults)

	// 系统接口
	mux.HandleFunc("/api/categories", s.handleCategories)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/pocs/reload", s.handlePOCReload)
	mux.HandleFunc("/api/health", s.handleHealth)

	// 启用CORS
	corsMux := s.corsMiddleware(mux)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: corsMux,
	}

	return s
}

// corsMiddleware CORS中间件
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Start 启动服务器
func (s *Server) Start() error {
	log.Printf("API服务器启动，监听 %s", s.server.Addr)
	return s.server.ListenAndServe()
}

// Stop 停止服务器
func (s *Server) Stop() error {
	if s.scanCancel != nil {
		s.scanCancel()
	}
	return s.server.Shutdown(context.Background())
}

// sendJSON 发送JSON响应
func (s *Server) sendJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

// sendError 发送错误响应
func (s *Server) sendError(w http.ResponseWriter, code int, message string) {
	s.sendJSON(w, code, map[string]interface{}{
		"error": message,
	})
}

// ==================== POC管理接口 ====================

// handlePOCs 处理POC列表请求
func (s *Server) handlePOCs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 获取查询参数
		category := r.URL.Query().Get("category")
		keyword := r.URL.Query().Get("keyword")

		var pocs []*poc.POC
		if category != "" {
			pocs = s.pocManager.GetPOCsByCategory(category)
		} else if keyword != "" {
			pocs = s.pocManager.SearchPOC(keyword)
		} else {
			pocs = s.pocManager.GetPOCs()
		}

		s.sendJSON(w, http.StatusOK, map[string]interface{}{
			"count": len(pocs),
			"data":  pocs,
		})

	case http.MethodDelete:
		// 批量删除POC
		var ids []string
		if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
			s.sendError(w, http.StatusBadRequest, "无效的请求体")
			return
		}

		deleted := 0
		for _, id := range ids {
			if s.pocManager.DeletePOC(id) {
				deleted++
			}
		}

		s.sendJSON(w, http.StatusOK, map[string]interface{}{
			"deleted": deleted,
		})

	default:
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
	}
}

// handlePOCByID 处理单个POC请求
func (s *Server) handlePOCByID(w http.ResponseWriter, r *http.Request) {
	// 提取POC ID
	id := r.URL.Path[len("/api/pocs/"):]
	if id == "" {
		s.sendError(w, http.StatusBadRequest, "POC ID不能为空")
		return
	}

	switch r.Method {
	case http.MethodGet:
		poc, ok := s.pocManager.GetPOC(id)
		if !ok {
			s.sendError(w, http.StatusNotFound, "POC不存在")
			return
		}
		s.sendJSON(w, http.StatusOK, poc)

	case http.MethodDelete:
		if s.pocManager.DeletePOC(id) {
			s.sendJSON(w, http.StatusOK, map[string]string{
				"message": "POC已删除",
			})
		} else {
			s.sendError(w, http.StatusNotFound, "POC不存在")
		}

	default:
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
	}
}

// handlePOCUpload 处理POC上传
func (s *Server) handlePOCUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	// 解析multipart表单
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB
		s.sendError(w, http.StatusBadRequest, "解析表单失败")
		return
	}

	// 获取上传的文件
	file, header, err := r.FormFile("file")
	if err != nil {
		s.sendError(w, http.StatusBadRequest, "获取文件失败")
		return
	}
	defer file.Close()

	// 读取文件内容
	data, err := io.ReadAll(file)
	if err != nil {
		s.sendError(w, http.StatusInternalServerError, "读取文件失败")
		return
	}

	// 保存文件
	category := r.FormValue("category")
	if category == "" {
		category = "others"
	}

	// 确保目录存在
	pocsDir := filepath.Join("..", "pocs", category)
	if err := os.MkdirAll(pocsDir, 0755); err != nil {
		s.sendError(w, http.StatusInternalServerError, "创建目录失败")
		return
	}

	filePath := filepath.Join(pocsDir, header.Filename)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		s.sendError(w, http.StatusInternalServerError, "保存文件失败")
		return
	}

	// 重新加载POC
	if _, err := s.pocManager.LoadFromFile(filePath); err != nil {
		s.sendError(w, http.StatusInternalServerError, "加载POC失败: "+err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]string{
		"message": "POC上传成功",
		"path":    filePath,
	})
}

// handlePOCExport 处理POC导出
func (s *Server) handlePOCExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	var req struct {
		Category string   `json:"category"`
		IDs      []string `json:"ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "无效的请求体")
		return
	}

	// 按分类导出
	if req.Category != "" {
		// 返回POC列表
		pocs := s.pocManager.GetPOCsByCategory(req.Category)
		s.sendJSON(w, http.StatusOK, map[string]interface{}{
			"count": len(pocs),
			"data":  pocs,
		})
		return
	}

	// 按ID导出
	if len(req.IDs) > 0 {
		pocs := make([]*poc.POC, 0, len(req.IDs))
		for _, id := range req.IDs {
			if p, ok := s.pocManager.GetPOC(id); ok {
				pocs = append(pocs, p)
			}
		}
		s.sendJSON(w, http.StatusOK, map[string]interface{}{
			"count": len(pocs),
			"data":  pocs,
		})
		return
	}

	s.sendError(w, http.StatusBadRequest, "请指定category或ids")
}

// ==================== 扫描接口 ====================

// handleScanStart 处理开始扫描请求
func (s *Server) handleScanStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	var req struct {
		Targets   []string `json:"targets"`
		POCID     string   `json:"poc_id"`
		Category  string   `json:"category"`
		MaxWorkers int     `json:"max_workers"`
		Timeout   int      `json:"timeout"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "无效的请求体")
		return
	}

	// 验证参数
	if len(req.Targets) == 0 {
		s.sendError(w, http.StatusBadRequest, "targets不能为空")
		return
	}

	// 停止当前扫描
	if s.scanCtx != nil {
		s.scanCancel()
	}

	// 创建新的扫描上下文
	s.scanCtx, s.scanCancel = context.WithCancel(context.Background())

	// 创建扫描请求
	scanReq := &scanner.ScanRequest{
		Targets:   req.Targets,
		POCID:     req.POCID,
		Category:  req.Category,
		MaxWorkers: req.MaxWorkers,
		Timeout:   req.Timeout,
	}

	// 创建扫描会话
	s.scanMu.Lock()
	s.scanResult = &ScanSession{
		ID:         fmt.Sprintf("scan-%d", time.Now().Unix()),
		Status:     "running",
		Results:    make([]*poc.ScanResult, 0),
		StartTime:  time.Now(),
		TargetList: req.Targets,
		POCID:      req.POCID,
		Category:   req.Category,
		MaxWorkers: req.MaxWorkers,
		Timeout:    req.Timeout,
		Metadata:   make(map[string]interface{}),
	}
	s.scanMu.Unlock()

	// 启动扫描
	go s.runScan(scanReq)

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"message": "扫描已启动",
		"scan_id": s.scanResult.ID,
	})
}

// runScan 运行扫描
func (s *Server) runScan(req *scanner.ScanRequest) {
	resultChan, progress := s.scanner.Scan(s.scanCtx, req)

	// 处理结果
	for result := range resultChan {
		s.scanMu.Lock()
		s.scanResult.Results = append(s.scanResult.Results, result)
		s.scanResult.Progress = progress
		s.scanMu.Unlock()
	}

	// 更新状态
	s.scanMu.Lock()
	s.scanResult.Status = "completed"
	s.scanResult.EndTime = time.Now()
	s.scanResult.Progress = s.scanner.GetProgress()
	s.scanMu.Unlock()
}

// handleScanStop 处理停止扫描请求
func (s *Server) handleScanStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	if s.scanCancel != nil {
		s.scanCancel()
		s.scanMu.Lock()
		s.scanResult.Status = "stopped"
		s.scanResult.EndTime = time.Now()
		s.scanMu.Unlock()

		s.sendJSON(w, http.StatusOK, map[string]string{
			"message": "扫描已停止",
		})
	} else {
		s.sendError(w, http.StatusBadRequest, "没有正在运行的扫描")
	}
}

// handleScanStatus 处理扫描状态请求
func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	s.scanMu.RLock()
	defer s.scanMu.RUnlock()

	if s.scanResult.ID == "" {
		s.sendError(w, http.StatusNotFound, "没有扫描记录")
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"scan_id":  s.scanResult.ID,
		"status":   s.scanResult.Status,
		"progress": s.scanResult.Progress,
		"start_time": s.scanResult.StartTime,
		"end_time": s.scanResult.EndTime,
	})
}

// handleScanResults 处理扫描结果请求
func (s *Server) handleScanResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	// 获取查询参数
	vulnerableOnly := r.URL.Query().Get("vulnerable") == "true"
	severity := r.URL.Query().Get("severity")

	s.scanMu.RLock()
	defer s.scanMu.RUnlock()

	if s.scanResult.ID == "" {
		s.sendError(w, http.StatusNotFound, "没有扫描记录")
		return
	}

	// 过滤结果
	results := s.scanResult.Results
	if vulnerableOnly || severity != "" {
		filtered := make([]*poc.ScanResult, 0)
		for _, r := range results {
			if vulnerableOnly && !r.Vulnerable {
				continue
			}
			if severity != "" && r.Severity != severity {
				continue
			}
			filtered = append(filtered, r)
		}
		results = filtered
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"scan_id":  s.scanResult.ID,
		"total":    len(s.scanResult.Results),
		"filtered": len(results),
		"data":     results,
	})
}

// ==================== 系统接口 ====================

// handleCategories 处理分类列表请求
func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	categories := s.pocManager.GetCategories()

	// 添加统计信息
	categoryStats := make([]map[string]interface{}, 0)
	for _, cat := range categories {
		categoryStats = append(categoryStats, map[string]interface{}{
			"name":  cat,
			"count": s.pocManager.GetPOCCountByCategory(cat),
		})
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"categories": categories,
		"stats":      categoryStats,
	})
}

// handleStats 处理统计信息请求
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	// POC统计
	pocCount := s.pocManager.GetPOCCount()
	categories := s.pocManager.GetCategories()

	categoryStats := make([]map[string]interface{}, 0)
	for _, cat := range categories {
		categoryStats = append(categoryStats, map[string]interface{}{
			"name":  cat,
			"count": s.pocManager.GetPOCCountByCategory(cat),
		})
	}

	// 扫描统计
	var vulnerableCount, scanTotal int
	s.scanMu.RLock()
	if s.scanResult.Progress != nil {
		vulnerableCount = s.scanResult.Progress.Vulnerable
		scanTotal = s.scanResult.Progress.Completed
	}
	s.scanMu.RUnlock()

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"poc_count":   pocCount,
		"categories":  categoryStats,
		"scan_total":  scanTotal,
		"vulnerable":  vulnerableCount,
	})
}

// handlePOCReload 处理POC重载请求
func (s *Server) handlePOCReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	// 从pocs目录加载
	pocsDir := filepath.Join("..", "pocs")
	if err := s.pocManager.LoadFromDir(pocsDir); err != nil {
		s.sendError(w, http.StatusInternalServerError, "加载POC失败: "+err.Error())
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"message": "POC已重载",
		"count":   s.pocManager.GetPOCCount(),
	})
}

// handleHealth 健康检查
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.sendError(w, http.StatusMethodNotAllowed, "不支持的请求方法")
		return
	}

	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"time":   time.Now().Unix(),
	})
}
