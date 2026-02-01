package poc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// POC 漏洞证明概念结构体
type POC struct {
	Name        string            `yaml:"name" json:"name"`
	ID          string            `yaml:"id" json:"id"`
	Category    string            `yaml:"category" json:"category"`
	Severity    string            `yaml:"severity" json:"severity"`
	Description string            `yaml:"description" json:"description"`
	Author      string            `yaml:"author" json:"author"`
	Version     string            `yaml:"version" json:"version"`
	References  []string          `yaml:"references,omitempty" json:"references,omitempty"`
	Tags        []string          `yaml:"tags,omitempty" json:"tags,omitempty"`
	Target      Target            `yaml:"target" json:"target"`
	Conditions  []Condition       `yaml:"conditions" json:"conditions"`
	Metadata    map[string]string `yaml:"-" json:"metadata"` // 运行时元数据
	FilePath    string            `yaml:"-" json:"-"` // 新增：记录物理文件路径，不序列化
}

// Target 目标配置
type Target struct {
	Protocol string            `yaml:"protocol" json:"protocol"`
	Path     string            `yaml:"path,omitempty" json:"path,omitempty"`
	Method   string            `yaml:"method" json:"method"`
	Headers  map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Body     string            `yaml:"body,omitempty" json:"body,omitempty"`
	Timeout  int               `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// Condition 检测条件
type Condition struct {
	Type     string      `yaml:"type" json:"type"`
	Operator string      `yaml:"operator" json:"operator"`
	Value    interface{} `yaml:"value" json:"value"`
	Name     string      `yaml:"name,omitempty" json:"name,omitempty"`
	Position string      `yaml:"position,omitempty" json:"position,omitempty"`
}

// ScanResult 扫描结果
type ScanResult struct {
	POCID      string  `json:"poc_id"`
	POCName    string  `json:"poc_name"`
	Target     string  `json:"target"`
	Vulnerable bool    `json:"vulnerable"`
	Message    string  `json:"message"`
	Details    string  `json:"details"`
	Severity   string  `json:"severity"`
}

// POCManager POC管理器
type POCManager struct {
	pocs      map[string]*POC // POC ID -> POC
	categories []string       // 支持的分类
	mu        sync.RWMutex
}

// NewPOCManager 创建POC管理器
func NewPOCManager() *POCManager {
	return &POCManager{
		pocs:      make(map[string]*POC),
		categories: []string{"cve", "vendor", "others"},
	}
}

// LoadFromDir 从目录加载POC
func (pm *POCManager) LoadFromDir(dir string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 清空现有POC
	pm.pocs = make(map[string]*POC)

	// 遍历目录
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只处理.yaml或.yml文件
		if !strings.HasSuffix(strings.ToLower(path), ".yaml") &&
			!strings.HasSuffix(strings.ToLower(path), ".yml") {
			return nil
		}

		// 读取文件
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("读取文件 %s 失败: %w", path, err)
		}

		// 解析YAML
		var poc POC
		if err := yaml.Unmarshal(data, &poc); err != nil {
			return fmt.Errorf("解析文件 %s 失败: %w", path, err)
		}

		poc.FilePath = path

		// 存储POC
		pm.pocs[poc.ID] = &poc

		return nil
	})

	return err
}

// LoadFromFile 从文件加载单个POC
func (pm *POCManager) LoadFromFile(filepath string) (*POC, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	var poc POC
	if err := yaml.Unmarshal(data, &poc); err != nil {
		return nil, fmt.Errorf("解析POC失败: %w", err)
	}

	poc.FilePath = filepath

	// 验证必填字段
	if err := pm.validatePOC(&poc); err != nil {
		return nil, fmt.Errorf("POC验证失败: %w", err)
	}

	pm.mu.Lock()
	pm.pocs[poc.ID] = &poc
	pm.mu.Unlock()

	return &poc, nil
}

// validatePOC 验证POC完整性
func (pm *POCManager) validatePOC(poc *POC) error {
	if poc.Name == "" {
		return fmt.Errorf("name字段为空")
	}
	if poc.ID == "" {
		return fmt.Errorf("id字段为空")
	}
	if !pm.isValidCategory(poc.Category) {
		return fmt.Errorf("无效的category: %s", poc.Category)
	}
	if !pm.isValidSeverity(poc.Severity) {
		return fmt.Errorf("无效的severity: %s", poc.Severity)
	}
	if poc.Description == "" {
		return fmt.Errorf("description字段为空")
	}
	if poc.Author == "" {
		return fmt.Errorf("author字段为空")
	}
	if poc.Version == "" {
		return fmt.Errorf("version字段为空")
	}
	if len(poc.Conditions) == 0 {
		return fmt.Errorf("conditions为空")
	}

	return nil
}

// isValidCategory 验证分类是否有效
func (pm *POCManager) isValidCategory(category string) bool {
	for _, c := range pm.categories {
		if c == category {
			return true
		}
	}
	return false
}

// isValidSeverity 验证风险等级是否有效
func (pm *POCManager) isValidSeverity(severity string) bool {
	validSeverities := []string{"Critical", "High", "Medium", "Low", "Info"}
	for _, s := range validSeverities {
		if s == severity {
			return true
		}
	}
	return false
}

// GetPOC 获取POC
func (pm *POCManager) GetPOC(id string) (*POC, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	poc, ok := pm.pocs[id]
	return poc, ok
}

// GetPOCs 获取所有POC
func (pm *POCManager) GetPOCs() []*POC {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pocs := make([]*POC, 0, len(pm.pocs))
	for _, poc := range pm.pocs {
		pocs = append(pocs, poc)
	}
	return pocs
}

// GetPOCsByCategory 按分类获取POC
func (pm *POCManager) GetPOCsByCategory(category string) []*POC {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pocs := make([]*POC, 0)
	for _, poc := range pm.pocs {
		if poc.Category == category {
			pocs = append(pocs, poc)
		}
	}
	return pocs
}

// GetCategories 获取所有分类
func (pm *POCManager) GetCategories() []string {
	return pm.categories
}

// ExportPOC 导出POC到文件
func (pm *POCManager) ExportPOC(id, filepath string) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	poc, ok := pm.pocs[id]
	if !ok {
		return fmt.Errorf("POC不存在: %s", id)
	}

	data, err := yaml.Marshal(poc)
	if err != nil {
		return fmt.Errorf("序列化POC失败: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	return nil
}

// ExportPOCsByCategory 按分类导出POC
func (pm *POCManager) ExportPOCsByCategory(category, dir string) error {
	pocs := pm.GetPOCsByCategory(category)

	for _, poc := range pocs {
		filename := fmt.Sprintf("%s.yaml", poc.ID)
		filepath := fmt.Sprintf("%s/%s", dir, filename)

		data, err := yaml.Marshal(poc)
		if err != nil {
			return fmt.Errorf("序列化POC %s 失败: %w", poc.ID, err)
		}

		if err := os.WriteFile(filepath, data, 0644); err != nil {
			return fmt.Errorf("写入文件 %s 失败: %w", filepath, err)
		}
	}

	return nil
}

// DeletePOC 删除POC
func (pm *POCManager) DeletePOC(id string) bool {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    // 1. 查找是否存在
    poc, ok := pm.pocs[id]
    if !ok {
        return false
    }

    // 2. 尝试删除物理文件
    if poc.FilePath != "" {
        err := os.Remove(poc.FilePath)
        if err != nil {
            // 如果文件删除失败（可能权限不足或文件已被手动删除），可以记录日志
            fmt.Printf("警告: 物理文件删除失败 [%s]: %v\n", poc.FilePath, err)
            // 依然继续，或者根据业务逻辑返回 false
        }
    }

    // 3. 从内存 map 中删除
    delete(pm.pocs, id)
    return true
}

// GetPOCCount 获取POC数量
func (pm *POCManager) GetPOCCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return len(pm.pocs)
}

// GetPOCCountByCategory 获取指定分类的POC数量
func (pm *POCManager) GetPOCCountByCategory(category string) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	count := 0
	for _, poc := range pm.pocs {
		if poc.Category == category {
			count++
		}
	}
	return count
}

// SearchPOC 搜索POC
func (pm *POCManager) SearchPOC(keyword string) []*POC {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	keyword = strings.ToLower(keyword)
	pocs := make([]*POC, 0)

	for _, poc := range pm.pocs {
		if strings.Contains(strings.ToLower(poc.Name), keyword) ||
			strings.Contains(strings.ToLower(poc.ID), keyword) ||
			strings.Contains(strings.ToLower(poc.Description), keyword) {
			pocs = append(pocs, poc)
		}
	}

	return pocs
}
