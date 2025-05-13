// 主JavaScript文件

document.addEventListener('DOMContentLoaded', function() {
    // 初始化工具提示
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // 初始化弹出框
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // 添加动画效果
    document.querySelectorAll('.card').forEach(function(card) {
        card.classList.add('fade-in');
    });

    // 自动隐藏警告框
    setTimeout(function() {
        document.querySelectorAll('.alert:not(.no-auto-close)').forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // 确认删除操作
    document.querySelectorAll('.confirm-delete').forEach(function(button) {
        button.addEventListener('click', function(e) {
            if (!confirm('确定要删除吗？此操作无法撤销。')) {
                e.preventDefault();
            }
        });
    });

    // 处理MCP工具状态切换
    document.querySelectorAll('.toggle-status').forEach(function(checkbox) {
        checkbox.addEventListener('change', function() {
            const toolId = this.dataset.toolId;
            const status = this.checked;
            
            fetch(`/api/mcp-tools/${toolId}/status`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ enabled: status })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('状态已更新', 'success');
                } else {
                    showNotification('更新失败: ' + data.message, 'danger');
                    // 恢复原状态
                    this.checked = !status;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showNotification('更新失败，请重试', 'danger');
                // 恢复原状态
                this.checked = !status;
            });
        });
    });

    // 动态表单验证
    const forms = document.querySelectorAll('.needs-validation');
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // 状态刷新
    const statusRefresh = document.getElementById('status-refresh');
    if (statusRefresh) {
        statusRefresh.addEventListener('click', function() {
            window.location.reload();
        });
    }

    // 密码确认验证
    const passwordForm = document.querySelector('form[action="/security/password"]');
    if (passwordForm) {
        passwordForm.addEventListener('submit', function(e) {
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            if (newPassword !== confirmPassword) {
                e.preventDefault();
                alert('新密码和确认密码不匹配');
            }
        });
    }

    // JSON配置编辑器
    const jsonEditor = document.getElementById('config-json');
    if (jsonEditor) {
        jsonEditor.addEventListener('blur', function() {
            try {
                const json = JSON.parse(jsonEditor.value);
                jsonEditor.value = JSON.stringify(json, null, 2);
                jsonEditor.classList.remove('is-invalid');
            } catch (e) {
                jsonEditor.classList.add('is-invalid');
            }
        });
    }
});

// 显示通知
function showNotification(message, type = 'info') {
    const container = document.querySelector('.container');
    if (!container) return;
    
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show`;
    notification.role = 'alert';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    // 将通知插入到容器的最上方
    container.insertBefore(notification, container.firstChild);
    
    // 5秒后自动关闭
    setTimeout(() => {
        const alert = new bootstrap.Alert(notification);
        alert.close();
    }, 5000);
}

// 复制到剪贴板
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showNotification('已复制到剪贴板', 'success');
    }, function(err) {
        showNotification('复制失败', 'danger');
        console.error('无法复制内容: ', err);
    });
}

// 动态加载数据
function loadData(url, targetElement, errorMessage = '加载数据失败') {
    const target = document.querySelector(targetElement);
    if (!target) return;
    
    target.innerHTML = '<div class="text-center p-3"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">加载中...</span></div></div>';
    
    fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            target.innerHTML = '';
            if (typeof renderData === 'function') {
                renderData(data, target);
            } else {
                console.error('renderData function is not defined');
                target.innerHTML = '<div class="alert alert-warning">未定义数据渲染函数</div>';
            }
        })
        .catch(error => {
            console.error('Fetch Error:', error);
            target.innerHTML = `<div class="alert alert-danger">${errorMessage}: ${error.message}</div>`;
        });
}

// 暗黑模式切换（如果需要）
function toggleDarkMode() {
    const isDarkMode = localStorage.getItem('darkMode') === 'true';
    localStorage.setItem('darkMode', !isDarkMode);
    document.body.classList.toggle('dark-mode', !isDarkMode);
}

// 检查是否已启用暗黑模式
function checkDarkMode() {
    const isDarkMode = localStorage.getItem('darkMode') === 'true';
    document.body.classList.toggle('dark-mode', isDarkMode);
} 