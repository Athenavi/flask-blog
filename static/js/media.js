function closeVideo() {
    document.getElementById("video-image").src = ""; // 清空视频源
    document.getElementById("video-popup").classList.add("hidden"); // 隐藏弹窗
}

let editMode = false;

function toggleEditMode() {
    editMode = !editMode;
    const checkboxes = document.querySelectorAll('.checkbox-container');
    const batchBtn = document.getElementById('batch-delete-btn');
    const editBtn = document.getElementById('edit-mode-btn');

    checkboxes.forEach(checkbox => {
        checkbox.style.display = editMode ? 'block' : 'none';
    });
    batchBtn.classList.toggle('hidden', !editMode);
    editBtn.textContent = editMode ? '退出编辑' : '编辑模式';
}

function updateSelectionCount() {
    const selected = document.querySelectorAll('.file-checkbox:checked');
    const batchBtn = document.getElementById('batch-delete-btn');
    batchBtn.textContent = `删除选中项 (${selected.length})`;
}

async function batchDelete() {
    const ids = Array.from(document.querySelectorAll('.file-checkbox:checked'))
        .map(checkbox => checkbox.dataset.fileId);

    // 检查是否选择了文件
    if (ids.length === 0) {
        showResultMessage('请先选择要删除的文件', 'yellow');
        return;
    }

    try {
        const response = await fetch(`/media?file-id-list=${ids.join(',')}`, {
            method: 'DELETE',
            credentials: 'include',
        });

        const result = await response.json();
        if (response.ok) {
            showResultMessage(`成功删除 ${result.deleted_count} 个文件`, 'green');
            // 刷新页面以更新列表
            setTimeout(() => location.reload(), 1500);
        } else {
            showResultMessage(result.message || '删除失败', 'red');
        }
    } catch (error) {
        showResultMessage('网络请求失败: ' + error.message, 'red');
    }
}

function showResultMessage(text, colorClass) {
    const div = document.getElementById('result-message');
    div.className = `${colorClass} bg-${colorClass}-100 border-${colorClass}-400 text-${colorClass}-700`;
    div.textContent = text;
    div.classList.remove('hidden');
    setTimeout(() => div.classList.add('hidden'), 3000);
}

// 过滤媒体类型
function filterMedia(btn, type) {
    // 移除所有按钮的激活样式
    document.querySelectorAll('.filter-btn').forEach(button => {
        button.classList.remove('bg-blue-500', 'text-white');
        button.classList.add('bg-gray-200');
    });

    // 添加当前按钮的激活样式
    btn.classList.add('bg-blue-500', 'text-white');
    btn.classList.remove('bg-gray-200');

    // 遍历所有媒体项
    document.querySelectorAll('li[data-type]').forEach(item => {
        const itemType = item.getAttribute('data-type');
        if (type === 'all') {
            item.style.display = 'block'; // 显示所有
        } else {
            item.style.display = itemType === type ? 'block' : 'none'; // 按类型过滤
        }
    });

    // 更新复选框计数（如果有需要）
    updateSelectionCount && updateSelectionCount();
}

function startVideo(hash) {
    const videoSrc = `/shared?data=${hash}`;
    document.getElementById("video-image").src = videoSrc;
    document.getElementById("video-popup").classList.remove("hidden");
}
