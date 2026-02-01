#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞扫描器图形化界面
"""

import json
import os
import sys
import threading
from datetime import datetime
from typing import List, Optional
import yaml
import requests
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QGroupBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QComboBox,
    QSpinBox,
    QFileDialog,
    QMessageBox,
    QProgressBar,
    QSplitter,
    QCheckBox,
    QHeaderView,
    QMenu,
    QAction,
)

# API配置
API_BASE_URL = "http://localhost:8080/api"


class VulnerabilityScannerGUI(QMainWindow):
    """漏洞扫描器主窗口"""

    def __init__(self):
        super().__init__()
        self.scan_running = False
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.update_scan_status)
        self.init_ui()

    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle("zmscan v1.0.0")
        self.setGeometry(100, 100, 1200, 800)

        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 创建主布局
        main_layout = QVBoxLayout(central_widget)

        # 创建工具栏
        toolbar_layout = self.create_toolbar()
        main_layout.addLayout(toolbar_layout)

        # 创建标签页
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # 创建各个标签页
        self.create_scan_tab()
        self.create_pocs_tab()
        self.create_results_tab()
        self.create_settings_tab()

        # 状态栏
        self.statusBar().showMessage("就绪")

        # 加载初始数据
        QTimer.singleShot(100, self.load_initial_data)

    def create_toolbar(self) -> QHBoxLayout:
        """创建工具栏"""
        layout = QHBoxLayout()

        # 连接状态指示
        self.connection_label = QLabel("API: 连接中...")
        self.connection_label.setStyleSheet("color: yellow;")
        layout.addWidget(self.connection_label)

        layout.addStretch()

        # 检查连接
        self.check_connection()

        return layout

    def create_scan_tab(self):
        """创建扫描标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 目标配置区域
        target_group = QGroupBox("目标配置")
        target_layout = QVBoxLayout()

        # IP地址输入
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP地址/域名:"))
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText(
            "示例: 192.168.1.1 或 192.168.1.1-192.168.1.100"
        )
        ip_layout.addWidget(self.ip_input)
        target_layout.addLayout(ip_layout)

        # 端口输入
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("端口:"))
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("示例: 80,443 或 8000-9000")
        self.port_input.setText("80,443")
        port_layout.addWidget(self.port_input)
        target_layout.addLayout(port_layout)

        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        # POC配置区域
        poc_group = QGroupBox("POC配置")
        poc_layout = QVBoxLayout()

        # POC分类与搜索
        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel("POC分类:"))
        self.category_combo = QComboBox()
        self.category_combo.addItem("全部", "")
        self.category_combo.addItem("CVE", "cve")
        self.category_combo.addItem("厂商漏洞", "vendor")
        self.category_combo.addItem("其他", "others")
        self.category_combo.currentIndexChanged.connect(self.filter_pocs)
        filter_layout.addWidget(self.category_combo)

        # 新增：搜索框
        filter_layout.addSpacing(20)
        filter_layout.addWidget(QLabel("搜索:"))
        self.scan_search_input = QLineEdit()
        self.scan_search_input.setPlaceholderText("关键词搜索...")
        self.scan_search_input.textChanged.connect(self.filter_pocs)
        filter_layout.addWidget(self.scan_search_input)

        # 新增：全选复选框
        filter_layout.addSpacing(20)
        self.select_all_check = QCheckBox("全选")
        self.select_all_check.stateChanged.connect(self.toggle_select_all)
        filter_layout.addWidget(self.select_all_check)

        filter_layout.addStretch()
        poc_layout.addLayout(filter_layout)

        # POC选择表格
        self.poc_table = QTableWidget()
        self.poc_table.setColumnCount(4)
        self.poc_table.setHorizontalHeaderLabels(["选择", "ID", "名称", "风险等级"])
        self.poc_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.poc_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.poc_table.setEditTriggers(QTableWidget.NoEditTriggers)
        poc_layout.addWidget(self.poc_table)

        poc_group.setLayout(poc_layout)
        layout.addWidget(poc_group)

        # 扫描配置区域
        scan_group = QGroupBox("扫描配置")
        scan_layout = QHBoxLayout()

        scan_layout.addWidget(QLabel("并发数:"))
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, 200)
        self.workers_spin.setValue(50)
        scan_layout.addWidget(self.workers_spin)

        scan_layout.addWidget(QLabel("超时(秒):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(10)
        scan_layout.addWidget(self.timeout_spin)

        scan_layout.addStretch()

        # 扫描按钮
        self.start_scan_btn = QPushButton("开始扫描")
        self.start_scan_btn.clicked.connect(self.start_scan)
        self.start_scan_btn.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold;"
        )
        scan_layout.addWidget(self.start_scan_btn)

        self.stop_scan_btn = QPushButton("停止扫描")
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.setStyleSheet(
            "background-color: #f44336; color: white; font-weight: bold;"
        )
        scan_layout.addWidget(self.stop_scan_btn)

        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)

        # 进度显示
        progress_group = QGroupBox("扫描进度")
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        progress_layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("准备就绪")
        progress_layout.addWidget(self.progress_label)

        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)

        self.tab_widget.addTab(tab, "扫描")

    def create_pocs_tab(self):
        """创建POC管理标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 工具栏
        tool_layout = QHBoxLayout()

        # 搜索框
        tool_layout.addWidget(QLabel("搜索:"))
        self.poc_search_input = QLineEdit()
        self.poc_search_input.setPlaceholderText("输入关键词搜索POC...")
        self.poc_search_input.textChanged.connect(self.search_pocs)
        tool_layout.addWidget(self.poc_search_input)

        # 分类筛选
        tool_layout.addWidget(QLabel("分类:"))
        self.poc_filter_combo = QComboBox()
        self.poc_filter_combo.addItem("全部", "")
        self.poc_filter_combo.addItem("CVE", "cve")
        self.poc_filter_combo.addItem("厂商漏洞", "vendor")
        self.poc_filter_combo.addItem("其他", "others")
        self.poc_filter_combo.currentIndexChanged.connect(self.filter_pocs)
        tool_layout.addWidget(self.poc_filter_combo)

        tool_layout.addStretch()

        # 按钮组
        reload_btn = QPushButton("重新加载POC")
        reload_btn.clicked.connect(self.reload_pocs)
        tool_layout.addWidget(reload_btn)

        import_btn = QPushButton("导入POC")
        import_btn.clicked.connect(self.import_poc)
        tool_layout.addWidget(import_btn)

        export_btn = QPushButton("导出POC")
        export_btn.clicked.connect(self.export_poc)
        tool_layout.addWidget(export_btn)

        self.delete_poc_btn = QPushButton("删除POC")
        self.delete_poc_btn.setStyleSheet(
            "background-color: #f44336; color: white; font-weight: bold;"
        )
        self.delete_poc_btn.clicked.connect(self.delete_poc)
        tool_layout.addWidget(self.delete_poc_btn)

        layout.addLayout(tool_layout)

        # POC列表表格
        self.poc_list_table = QTableWidget()
        self.poc_list_table.setColumnCount(7)
        self.poc_list_table.setHorizontalHeaderLabels(
            ["ID", "名称", "分类", "风险等级", "作者", "版本", "标签"]
        )
        self.poc_list_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.poc_list_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.poc_list_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.poc_list_table.setSelectionMode(QTableWidget.SingleSelection)
        layout.addWidget(self.poc_list_table)

        # 绑定点击事件，点击单元格时显示详情
        self.poc_list_table.itemClicked.connect(self.show_poc_detail)

        # POC详情区域
        detail_group = QGroupBox("POC详情")
        detail_layout = QVBoxLayout()
        self.poc_detail_text = QTextEdit()
        self.poc_detail_text.setReadOnly(True)
        detail_layout.addWidget(self.poc_detail_text)
        detail_group.setLayout(detail_layout)
        layout.addWidget(detail_group)

        self.tab_widget.addTab(tab, "POC管理")

    def show_poc_detail(self, item):
        """显示选中的POC详细信息"""
        row = item.row()
        # 获取第一列的 POC ID
        poc_id = self.poc_list_table.item(row, 0).text()

        try:
            # 重新从 API 获取该 POC 的完整数据（或从本地缓存中查找）
            params = {"keyword": poc_id}
            response = requests.get(f"{API_BASE_URL}/pocs", params=params, timeout=5)

            if response.status_code == 200:
                data = response.json()
                pocs = data.get("data", [])

                # 寻找匹配的 POC 记录
                selected_poc = next((p for p in pocs if p.get("id") == poc_id), None)

                if selected_poc:
                    # 格式化显示详情
                    detail_text = (
                        f"【POC ID】: {selected_poc.get('id')}\n"
                        f"【名称】: {selected_poc.get('name')}\n"
                        f"【风险等级】: {selected_poc.get('severity')}\n"
                        f"【分类】: {selected_poc.get('category')}\n"
                        f"【作者】: {selected_poc.get('author', '未知')}\n"
                        f"【版本】: {selected_poc.get('version', '1.0.0')}\n"
                        f"【标签】: {', '.join(selected_poc.get('tags', []))}\n"
                        f"{'-'*40}\n"
                        f"【描述】:\n{selected_poc.get('description', '暂无描述信息。')}\n\n"
                        f"【修复建议】:\n{selected_poc.get('remediation', '请关注厂商补丁更新。')}"
                    )
                    self.poc_detail_text.setText(detail_text)
            else:
                self.poc_detail_text.setText(
                    f"获取详情失败，API返回码: {response.status_code}"
                )
        except Exception as e:
            self.poc_detail_text.setText(f"读取详情出错: {str(e)}")

    def create_results_tab(self):
        """创建扫描结果标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 工具栏
        tool_layout = QHBoxLayout()

        tool_layout.addWidget(QLabel("筛选:"))

        self.vulnerable_only_check = QCheckBox("仅显示漏洞")
        self.vulnerable_only_check.stateChanged.connect(self.filter_results)
        tool_layout.addWidget(self.vulnerable_only_check)

        tool_layout.addWidget(QLabel("风险等级:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("全部", "")
        self.severity_combo.addItem("Critical", "Critical")
        self.severity_combo.addItem("High", "High")
        self.severity_combo.addItem("Medium", "Medium")
        self.severity_combo.addItem("Low", "Low")
        self.severity_combo.addItem("Info", "Info")
        self.severity_combo.currentIndexChanged.connect(self.filter_results)
        tool_layout.addWidget(self.severity_combo)

        tool_layout.addStretch()

        # 导出按钮
        export_results_btn = QPushButton("导出结果")
        export_results_btn.clicked.connect(self.export_results)
        tool_layout.addWidget(export_results_btn)

        clear_results_btn = QPushButton("清空结果")
        clear_results_btn.clicked.connect(self.clear_results)
        tool_layout.addWidget(clear_results_btn)

        layout.addLayout(tool_layout)

        # 结果统计
        stats_layout = QHBoxLayout()
        self.total_results_label = QLabel("总计: 0")
        stats_layout.addWidget(self.total_results_label)
        self.vulnerable_count_label = QLabel("存在漏洞: 0")
        self.vulnerable_count_label.setStyleSheet("color: red; font-weight: bold;")
        stats_layout.addWidget(self.vulnerable_count_label)
        layout.addLayout(stats_layout)

        # 结果表格
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels(
            ["目标", "POC名称", "风险等级", "是否存在漏洞", "消息", "扫描时间", "操作"]
        )
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(
            self.show_result_context_menu
        )
        layout.addWidget(self.results_table)

        # 结果详情
        result_detail_group = QGroupBox("结果详情")
        result_detail_layout = QVBoxLayout()
        self.result_detail_text = QTextEdit()
        self.result_detail_text.setReadOnly(True)
        result_detail_layout.addWidget(self.result_detail_text)
        result_detail_group.setLayout(result_detail_layout)
        layout.addWidget(result_detail_group)

        self.tab_widget.addTab(tab, "扫描结果")

    def create_settings_tab(self):
        """创建设置标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # API配置
        api_group = QGroupBox("API配置")
        api_layout = QVBoxLayout()

        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("API地址:"))
        self.api_url_input = QLineEdit()
        self.api_url_input.setText(API_BASE_URL)
        url_layout.addWidget(self.api_url_input)

        test_btn = QPushButton("测试连接")
        test_btn.clicked.connect(self.test_connection)
        url_layout.addWidget(test_btn)

        api_layout.addLayout(url_layout)
        api_group.setLayout(api_layout)
        layout.addWidget(api_group)

        # 统计信息
        stats_group = QGroupBox("系统统计")
        stats_layout = QVBoxLayout()

        self.poc_count_label = QLabel("POC总数: 0")
        stats_layout.addWidget(self.poc_count_label)

        self.category_stats_label = QLabel("分类统计: -")
        stats_layout.addWidget(self.category_stats_label)

        refresh_stats_btn = QPushButton("刷新统计")
        refresh_stats_btn.clicked.connect(self.load_stats)
        stats_layout.addWidget(refresh_stats_btn)

        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        layout.addStretch()
        self.tab_widget.addTab(tab, "设置")

    def delete_poc(self):
        """删除选中的POC"""
        # 1. 获取选中的行
        selected_rows = self.poc_list_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "警告", "请先在列表中选择一个要删除的POC")
            return

        row = selected_rows[0].row()
        poc_id = self.poc_list_table.item(row, 0).text()
        poc_name = self.poc_list_table.item(row, 1).text()

        # 2. 二次确认防止误删
        reply = QMessageBox.question(
            self,
            "确认删除",
            f"确定要删除以下 POC 吗？\n\nID: {poc_id}\n名称: {poc_name}\n\n注意：此操作不可撤销！",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            try:
                # 3. 调用后端 API 执行删除 (假设接口为 DELETE /api/pocs/{id})
                response = requests.delete(f"{API_BASE_URL}/pocs/{poc_id}", timeout=10)

                if response.status_code == 200:
                    QMessageBox.information(self, "成功", f"POC [{poc_id}] 已成功删除")
                    # 4. 刷新界面数据
                    self.load_pocs()
                    self.load_stats()
                    self.poc_detail_text.clear()  # 清空详情区域
                else:
                    QMessageBox.warning(
                        self, "失败", f"删除失败，服务器返回码: {response.status_code}"
                    )
            except Exception as e:
                QMessageBox.critical(self, "错误", f"请求删除过程中出错:\n{str(e)}")

    # ==================== API调用 ====================

    def check_connection(self):
        """检查API连接"""

        def _check():
            try:
                response = requests.get(f"{API_BASE_URL}/health", timeout=5)
                if response.status_code == 200:
                    self.connection_label.setText("API: 已连接")
                    self.connection_label.setStyleSheet("color: green;")
                else:
                    self.connection_label.setText("API: 连接异常")
                    self.connection_label.setStyleSheet("color: red;")
            except Exception as e:
                self.connection_label.setText("API: 无法连接")
                self.connection_label.setStyleSheet("color: red;")
                print(f"连接错误: {e}")

        threading.Thread(target=_check, daemon=True).start()

    def test_connection(self):
        """测试连接"""
        try:
            response = requests.get(f"{self.api_url_input.text()}/health", timeout=5)
            if response.status_code == 200:
                QMessageBox.information(self, "连接成功", "API连接正常！")
            else:
                QMessageBox.warning(
                    self, "连接失败", f"API返回状态码: {response.status_code}"
                )
        except Exception as e:
            QMessageBox.critical(self, "连接错误", f"无法连接到API:\n{str(e)}")

    def load_initial_data(self):
        """加载初始数据"""
        self.load_pocs()
        self.load_stats()

    def load_pocs(self):
        """加载POC列表"""
        try:
            params = {}
            current_tab = self.tab_widget.currentIndex()

            # 根据当前标签页获取分类和搜索关键词
            if current_tab == 0:  # 扫描标签页
                category = self.category_combo.currentData()
                keyword = self.scan_search_input.text().strip()
            else:  # POC管理标签页
                category = self.poc_filter_combo.currentData()
                keyword = self.poc_search_input.text().strip()

            if category:
                params["category"] = category
            if keyword:
                params["keyword"] = keyword

            response = requests.get(f"{API_BASE_URL}/pocs", params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pocs = data.get("data", [])
                self.update_poc_table(pocs)
                self.update_scan_poc_table(pocs)

                # 重新加载后重置全选状态
                if current_tab == 0:
                    self.select_all_check.setCheckState(Qt.Unchecked)
            else:
                self.statusBar().showMessage(f"加载POC失败: {response.status_code}")
        except Exception as e:
            self.statusBar().showMessage(f"加载POC错误: {str(e)}")

    def toggle_select_all(self, state):
        """切换全选/全不选"""
        # Qt.Checked (2) 为选中，Qt.Unchecked (0) 为不选
        check_state = Qt.Checked if state == Qt.Checked else Qt.Unchecked

        for row in range(self.poc_table.rowCount()):
            item = self.poc_table.item(row, 0)
            if item:
                item.setCheckState(check_state)

    def update_poc_table(self, pocs: List[dict]):
        """更新POC列表表格"""
        self.poc_list_table.setRowCount(len(pocs))

        for row, poc in enumerate(pocs):
            self.poc_list_table.setItem(row, 0, QTableWidgetItem(poc.get("id", "")))
            self.poc_list_table.setItem(row, 1, QTableWidgetItem(poc.get("name", "")))
            self.poc_list_table.setItem(
                row, 2, QTableWidgetItem(poc.get("category", ""))
            )
            self.poc_list_table.setItem(
                row, 3, QTableWidgetItem(poc.get("severity", ""))
            )
            self.poc_list_table.setItem(row, 4, QTableWidgetItem(poc.get("author", "")))
            self.poc_list_table.setItem(
                row, 5, QTableWidgetItem(poc.get("version", ""))
            )

            tags = ", ".join(poc.get("tags", []))
            self.poc_list_table.setItem(row, 6, QTableWidgetItem(tags))

            # 设置风险等级颜色
            severity_item = self.poc_list_table.item(row, 3)
            self.set_severity_color(severity_item, poc.get("severity", ""))

    def update_scan_poc_table(self, pocs: List[dict]):
        """更新扫描POC选择表格"""
        self.poc_table.setRowCount(len(pocs))

        for row, poc in enumerate(pocs):
            # 选择框
            check_item = QTableWidgetItem()
            check_item.setCheckState(Qt.Unchecked)
            self.poc_table.setItem(row, 0, check_item)

            self.poc_table.setItem(row, 1, QTableWidgetItem(poc.get("id", "")))
            self.poc_table.setItem(row, 2, QTableWidgetItem(poc.get("name", "")))

            severity_item = QTableWidgetItem(poc.get("severity", ""))
            self.poc_table.setItem(row, 3, severity_item)
            self.set_severity_color(severity_item, poc.get("severity", ""))

    def set_severity_color(self, item: QTableWidgetItem, severity: str):
        """设置风险等级颜色"""
        color_map = {
            "Critical": QColor(211, 47, 47),  # 红色
            "High": QColor(244, 67, 54),  # 深红
            "Medium": QColor(255, 152, 0),  # 橙色
            "Low": QColor(255, 193, 7),  # 黄色
            "Info": QColor(96, 125, 139),  # 灰色
        }
        if severity in color_map:
            item.setBackground(color_map[severity])
            item.setForeground(QColor("white"))

    def search_pocs(self):
        """搜索POC"""
        keyword = self.poc_search_input.text().strip()
        if not keyword:
            self.load_pocs()
            return

        try:
            params = {"keyword": keyword}
            response = requests.get(f"{API_BASE_URL}/pocs", params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.update_poc_table(data.get("data", []))
        except Exception as e:
            self.statusBar().showMessage(f"搜索POC错误: {str(e)}")

    def filter_pocs(self):
        """筛选POC"""
        self.load_pocs()

    def reload_pocs(self):
        """重新加载POC"""
        try:
            response = requests.post(f"{API_BASE_URL}/pocs/reload", timeout=30)
            if response.status_code == 200:
                data = response.json()
                QMessageBox.information(
                    self, "成功", f"已重新加载 {data.get('count', 0)} 个POC"
                )
                self.load_pocs()
                self.load_stats()
            else:
                QMessageBox.warning(self, "失败", f"重载失败: {response.status_code}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"重载POC错误:\n{str(e)}")

    def import_poc(self):
        """导入POC到服务器"""
        # 1. 打开文件选择对话框
        file_paths, _ = QFileDialog.getOpenFileNames(
            self, "选择POC文件", "", "YAML Files (*.yaml *.yml);;All Files (*)"
        )

        if not file_paths:
            return

        success_count = 0
        error_messages = []

        # 2. 遍历选中的文件并上传
        for path in file_paths:
            try:
                with open(path, "rb") as f:
                    files = {"file": (os.path.basename(path), f)}
                    # 如果当前选择了分类，则带上分类参数
                    category = self.poc_filter_combo.currentData()
                    data = {"category": category} if category else {}

                    response = requests.post(
                        f"{API_BASE_URL}/pocs/upload",
                        files=files,
                        data=data,
                        timeout=15,
                    )

                if response.status_code == 200:
                    success_count += 1
                else:
                    error_messages.append(f"{os.path.basename(path)}: {response.text}")

            except Exception as e:
                error_messages.append(f"{os.path.basename(path)}: {str(e)}")

        # 3. 结果反馈
        if success_count > 0:
            QMessageBox.information(
                self, "导入完成", f"成功导入 {success_count} 个POC！"
            )
            self.load_pocs()
            self.load_stats()

        if error_messages:
            QMessageBox.warning(self, "部分导入失败", "\n".join(error_messages))

    def export_poc(self):
        """将选中的POC导出为YAML格式"""
        # 1. 获取选中的行
        selected_rows = self.poc_list_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "操作取消", "请先在列表中选中一个POC再进行导出。")
            return

        row = selected_rows[0].row()
        poc_id = self.poc_list_table.item(row, 0).text()
        poc_name = self.poc_list_table.item(row, 1).text()

        # 2. 弹出保存对话框，默认后缀改为 .yaml
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出POC", f"{poc_id}.yaml", "YAML Files (*.yaml);;All Files (*)"
        )

        if not file_path:
            return

        try:
            # 3. 从服务器请求完整的POC数据
            params = {"keyword": poc_id}
            response = requests.get(f"{API_BASE_URL}/pocs", params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                pocs = data.get("data", [])

                # 匹配具体的POC对象
                selected_poc = next((p for p in pocs if p.get("id") == poc_id), None)

                if selected_poc:
                    # 4. 执行写入操作
                    with open(file_path, "w", encoding="utf-8") as f:
                        # 使用 yaml.dump 将字典转换为 YAML 字符串
                        # allow_unicode=True 确保中文不被转义为 \uXXXX
                        # sort_keys=False 保持原始字段顺序
                        yaml.dump(
                            selected_poc,
                            f,
                            allow_unicode=True,
                            sort_keys=False,
                            default_flow_style=False,
                        )

                    QMessageBox.information(
                        self,
                        "导出成功",
                        f"POC [{poc_name}] 已成功保存至：\n{file_path}",
                    )
                else:
                    QMessageBox.warning(
                        self, "未找到数据", "服务器未返回该POC的详细配置信息。"
                    )
            else:
                QMessageBox.warning(
                    self, "API错误", f"请求失败，错误码: {response.status_code}"
                )

        except Exception as e:
            QMessageBox.critical(
                self, "导出异常", f"在写入YAML文件时发生错误：\n{str(e)}"
            )

    def load_stats(self):
        """加载统计信息"""
        try:
            response = requests.get(f"{API_BASE_URL}/stats", timeout=10)
            if response.status_code == 200:
                data = response.json()
                self.poc_count_label.setText(f"POC总数: {data.get('poc_count', 0)}")

                category_text = []
                for cat in data.get("categories", []):
                    category_text.append(f"{cat.get('name')}: {cat.get('count')}")
                self.category_stats_label.setText(
                    "分类统计: " + ", ".join(category_text)
                )
        except Exception as e:
            self.statusBar().showMessage(f"加载统计错误: {str(e)}")

    # ==================== 扫描功能 ====================

    def parse_targets(self) -> List[str]:
        """解析目标列表"""
        ip_input = self.ip_input.text().strip()
        port_input = self.port_input.text().strip()

        if not ip_input:
            return []

        # 解析端口
        ports = []
        for p in port_input.split(","):
            p = p.strip()
            if "-" in p:
                start, end = p.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(p))

        # 解析IP
        targets = []
        if "-" in ip_input:
            # IP范围
            start_ip, end_ip = ip_input.split("-")
            # 简化处理，实际需要完整的IP范围解析
            targets = [f"{start_ip}:{p}" for p in ports]
        else:
            targets = [f"{ip_input}:{p}" for p in ports]

        return targets

    def get_selected_pocs(self) -> List[str]:
        """获取选中的POC"""
        poc_ids = []
        for row in range(self.poc_table.rowCount()):
            if self.poc_table.item(row, 0).checkState() == Qt.Checked:
                poc_id = self.poc_table.item(row, 1).text()
                poc_ids.append(poc_id)
        return poc_ids

    def start_scan(self):
        """开始扫描"""
        targets = self.parse_targets()
        if not targets:
            QMessageBox.warning(self, "警告", "请输入有效的目标地址和端口")
            return

        # 获取选中的POC或使用分类
        poc_ids = self.get_selected_pocs()
        category = self.category_combo.currentData()

        scan_data = {
            "targets": targets,
            "max_workers": self.workers_spin.value(),
            "timeout": self.timeout_spin.value(),
        }

        if poc_ids and len(poc_ids) == 1:
            scan_data["poc_id"] = poc_ids[0]
        elif category:
            scan_data["category"] = category

        try:
            response = requests.post(
                f"{API_BASE_URL}/scan/start", json=scan_data, timeout=10
            )

            if response.status_code == 200:
                self.scan_running = True
                self.start_scan_btn.setEnabled(False)
                self.stop_scan_btn.setEnabled(True)
                self.scan_timer.start(500)  # 每500ms更新一次

                # 切换到结果标签页
                self.tab_widget.setCurrentIndex(2)
                self.results_table.setRowCount(0)
                self.statusBar().showMessage("扫描进行中...")
            else:
                QMessageBox.warning(
                    self, "失败", f"启动扫描失败: {response.status_code}"
                )
        except Exception as e:
            QMessageBox.critical(self, "错误", f"启动扫描错误:\n{str(e)}")

    def stop_scan(self):
        """停止扫描"""
        try:
            response = requests.post(f"{API_BASE_URL}/scan/stop", timeout=10)
            if response.status_code == 200:
                self.statusBar().showMessage("扫描已停止")
            else:
                QMessageBox.warning(self, "失败", "停止扫描失败")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"停止扫描错误:\n{str(e)}")

    def update_scan_status(self):
        """更新扫描状态"""
        try:
            response = requests.get(f"{API_BASE_URL}/scan/status", timeout=5)
            if response.status_code == 200:
                data = response.json()
                progress = data.get("progress", {})

                total = progress.get("total", 0)
                completed = progress.get("completed", 0)
                vulnerable = progress.get("vulnerable", 0)

                # 更新进度条
                if total > 0:
                    percent = int(completed / total * 100)
                    self.progress_bar.setValue(percent)
                    self.progress_label.setText(
                        f"已完成: {completed}/{total}, 存在漏洞: {vulnerable}"
                    )

                # 更新结果表格
                self.update_results()

                # 检查扫描是否完成
                if data.get("status") in ["completed", "stopped"]:
                    self.scan_running = False
                    self.start_scan_btn.setEnabled(True)
                    self.stop_scan_btn.setEnabled(False)
                    self.scan_timer.stop()
                    self.statusBar().showMessage("扫描已完成")

        except Exception as e:
            print(f"更新扫描状态错误: {e}")

    def update_results(self):
        """更新扫描结果"""
        try:
            params = {}
            if self.vulnerable_only_check.isChecked():
                params["vulnerable"] = "true"
            severity = self.severity_combo.currentData()
            if severity:
                params["severity"] = severity

            response = requests.get(
                f"{API_BASE_URL}/scan/results", params=params, timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("data", [])

                self.results_table.setRowCount(len(results))

                for row, result in enumerate(results):
                    self.results_table.setItem(
                        row, 0, QTableWidgetItem(result.get("target", ""))
                    )
                    self.results_table.setItem(
                        row, 1, QTableWidgetItem(result.get("poc_name", ""))
                    )

                    severity_item = QTableWidgetItem(result.get("severity", ""))
                    self.results_table.setItem(row, 2, severity_item)
                    self.set_severity_color(severity_item, result.get("severity", ""))

                    vulnerable = result.get("vulnerable", False)
                    vulnerable_item = QTableWidgetItem("是" if vulnerable else "否")
                    vulnerable_item.setForeground(
                        QColor("red") if vulnerable else QColor("green")
                    )
                    self.results_table.setItem(row, 3, vulnerable_item)

                    self.results_table.setItem(
                        row, 4, QTableWidgetItem(result.get("message", ""))
                    )
                    self.results_table.setItem(
                        row, 5, QTableWidgetItem(datetime.now().strftime("%H:%M:%S"))
                    )

                    # 操作按钮
                    detail_btn = QPushButton("详情")
                    detail_btn.clicked.connect(
                        lambda _, r=row: self.show_result_detail(r)
                    )
                    self.results_table.setCellWidget(row, 6, detail_btn)

                # 更新统计
                self.total_results_label.setText(f"总计: {data.get('total', 0)}")

                # 计算漏洞数量
                all_results = data.get("data", [])
                vuln_count = sum(1 for r in all_results if r.get("vulnerable", False))
                self.vulnerable_count_label.setText(f"存在漏洞: {vuln_count}")

        except Exception as e:
            print(f"更新结果错误: {e}")

    def filter_results(self):
        """筛选结果"""
        self.update_results()

    def show_result_context_menu(self, pos):
        """显示结果右键菜单"""
        menu = QMenu(self)
        copy_action = QAction("复制目标", self)
        copy_action.triggered.connect(self.copy_target)
        menu.addAction(copy_action)
        menu.exec_(self.results_table.mapToGlobal(pos))

    def copy_target(self):
        """复制目标地址"""
        row = self.results_table.currentRow()
        if row >= 0:
            target = self.results_table.item(row, 0).text()
            QApplication.clipboard().setText(target)
            self.statusBar().showMessage(f"已复制: {target}")

    def show_result_detail(self, row: int):
        """显示结果详情"""
        try:
            response = requests.get(f"{API_BASE_URL}/scan/results", timeout=10)
            if response.status_code == 200:
                data = response.json()
                results = data.get("data", [])
                if row < len(results):
                    result = results[row]
                    detail = f"""目标: {result.get('target', '')}
POC名称: {result.get('poc_name', '')}
POC ID: {result.get('poc_id', '')}
风险等级: {result.get('severity', '')}
是否存在漏洞: {result.get('vulnerable', False)}
消息: {result.get('message', '')}
详情: {result.get('details', '')}
"""
                    self.result_detail_text.setText(detail)
        except Exception as e:
            self.result_detail_text.setText(f"获取详情错误: {str(e)}")

    def export_results(self):
        """导出结果"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存结果", "", "JSON Files (*.json);;Text Files (*.txt)"
        )

        if file_path:
            try:
                response = requests.get(f"{API_BASE_URL}/scan/results", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                    QMessageBox.information(self, "成功", "结果导出成功！")
                else:
                    QMessageBox.warning(self, "失败", "导出结果失败")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出错误:\n{str(e)}")

    def clear_results(self):
        """清空结果"""
        reply = QMessageBox.question(
            self, "确认", "确定要清空所有扫描结果吗？", QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.results_table.setRowCount(0)
            self.result_detail_text.clear()
            self.total_results_label.setText("总计: 0")
            self.vulnerable_count_label.setText("存在漏洞: 0")


def main():
    """主函数"""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # 设置应用信息
    app.setApplicationName("漏洞扫描器")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Security Team")

    # 创建并显示主窗口
    window = VulnerabilityScannerGUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
