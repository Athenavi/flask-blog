function checkDataHidden() {
    const replayDiv = document.getElementById('replayId');
    const resetButton = document.getElementById('resetButton');
    const currentValue = replayDiv.getAttribute('data-hidden');
    const replayTips = document.getElementById('replayTips');
    if (currentValue !== "0") {
        resetButton.style.display = 'block';
        replayTips.style.display = 'block';
    } else {
        resetButton.style.display = 'none'; // 隐藏按钮
        replayTips.style.display = 'none';
    }
}

function resetDataHidden() {
    const replayDiv = document.getElementById('replayId');
    const replayTips = document.getElementById('replayTips');
    replayDiv.setAttribute('data-hidden', '0');
    console.log('Data-hidden reset to 0');
    replayTips.innerHTML = ``;

    // 每次重置后检查按钮的显示状态
    checkDataHidden();
}

function getReplyId() {
    const replayDiv = document.getElementById('replayId');
    const hiddenValue = replayDiv.getAttribute('data-hidden');
    console.log('Current data-hidden value:', hiddenValue);
    return hiddenValue;
}

function updateReplyId(commentId, RepliedContent) {
    // 获取 div 元素
    const replayDiv = document.getElementById('replayId');
    const replayTips = document.getElementById('replayTips');
    replayDiv.setAttribute('data-hidden', commentId);
    replayTips.innerHTML = `reply:  ${RepliedContent}`;

    // 打印 commentId 和新的 data-hidden 值
    console.log('Comment ID:', commentId);
    console.log('New data-hidden value:', replayDiv.getAttribute('data-hidden'));
    checkDataHidden()
}

function toggleReplies(commentId) {
    const replies = document.getElementById('replies-' + commentId);
    if (replies.classList.contains('hidden')) {
        replies.classList.remove('hidden');
    } else {
        replies.classList.add('hidden');
    }
}

// 插入表情符号
function insertEmoji(emoji) {
    const commentBox = document.getElementById('comment');
    const start = commentBox.selectionStart;
    const end = commentBox.selectionEnd;

    commentBox.value = commentBox.value.substring(0, start) + emoji + commentBox.value.substring(end);
    commentBox.selectionStart = commentBox.selectionEnd = start + emoji.length;
    commentBox.focus();
}

// 提交评论
document.getElementById('submit-comment').addEventListener('click', async () => {
    const articleId = getParameterByName('aid');
    const commentContent = document.getElementById('comment').value;
    const replayId = getReplyId()

    if (!articleId || !commentContent) {
        document.getElementById('message').innerText = "当你提交评论时若多次出现此提示，则当前文章不可评论";
        return;
    }

    try {
        const response = await fetch('/api/comment', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                aid: articleId,
                'new-comment': commentContent,
                'pid': replayId
            })
        });

        const result = await response.json();
        if (response.ok) {
            document.getElementById('message').innerText = "评论成功！";
            document.getElementById('comment').value = "";
            const now = new Date();
            const formattedDate = `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}-${now.getDate().toString().padStart(2, '0')} ${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
            console.log(formattedDate);
            addMessage(commentContent, formattedDate);
        } else {
            document.getElementById('message').innerText = result.message || "评论失败。";
        }
    } catch (error) {
        console.error("提交评论时出错:", error);
        document.getElementById('message').innerText = "发生错误，请重试。";
    }
});

// 添加评论信息
function addMessage(message, date) {
    const commentsDiv = document.getElementById('comments');
    const defaultAvatar = "https://api.7trees.cn/avatar";
    const username = "(我)";
    let messageHTML = `
            <div class="bg-white p-4 rounded-lg shadow-md flex">
                <img src="${defaultAvatar}?${username}" alt="Avatar" class="w-10 h-10 rounded-full mr-4">
                <div class="flex-1">
                    <div class="font-semibold text-gray-700">${username}<div class="text-sm text-gray-500">${date}</div></div>
                    <div class="text-gray-800 mb-1">${message}</div>
                    <div class="text-sm text-gray-500 flex items-center">
                        <span class="mr-2"><i class="fas fa-desktop"></i> 设备</span>
                    </div>
                </div>
            </div>`;
    commentsDiv.innerHTML += messageHTML;
}

// 获取URL参数的函数
function getParameterByName(name) {
    name = name.replace(/[\[\]]/g, "\\$&");
    var url = window.location.href;
    var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)");
    var results = regex.exec(url);
    if (!results) return 0;
    if (!results[2]) return 0;
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}


// 显示举报模态框
function showReportModal(commentId, commentContent) {
    console.log('Showing report modal for comment ID:', commentId); // Debug log
    document.getElementById('ReportedCommentContent').innerText = commentContent;
    document.getElementById('reportForm').dataset.commentId = commentId;
    document.getElementById('ReportModal').style.display = 'block'; // 显示模态框
    document.getElementById('overlay').style.display = 'block'; // 显示覆盖层
}

function cancelReport() {
    document.getElementById('ReportModal').style.display = 'none';
    document.getElementById('overlay').style.display = 'none';
}

function submitReport(event) {
    event.preventDefault();
    const reportType = document.getElementById('reportType').value;
    const reportReason = document.getElementById('reportReason').value;
    const commentId = document.getElementById('reportForm').dataset.commentId;

    // 显示加载状态[6,10](@ref)
    Swal.fire({
        title: '提交中...',
        allowOutsideClick: false,
        didOpen: () => Swal.showLoading()
    });

    fetch('/api/report', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            'report-id': commentId,
            'report-reason': reportReason,
            'report-type': reportType
        })
    })
        .then(response => {
            if (response.ok) {
                // 成功提示[1,6](@ref)
                Swal.fire({
                    icon: 'success',
                    title: '举报已提交',
                    showConfirmButton: false,
                    timer: 1500
                }).then(() => {
                    cancelReport(); // 自动关闭弹窗后执行
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.message && !response.ok) {
                // 服务端返回的额外提示[9](@ref)
                Swal.fire({
                    icon: 'info',
                    title: data.message,
                    confirmButtonColor: '#3085d6'
                });
            }
        })
        .catch(error => {
            // 错误处理[6](@ref)
            Swal.fire({
                icon: 'error',
                title: '提交失败',
                text: '请检查网络后重试',
                confirmButtonText: '知道了'
            });
        });
}


function deleteThisComment(commentId, element) {
    // 确认对话框升级[8,10](@ref)
    Swal.fire({
        title: '确定删除？',
        text: "删除后将无法恢复此评论！",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#d33',
        cancelButtonColor: '#3085d6',
        confirmButtonText: '永久删除',
        cancelButtonText: '取消操作'
    }).then((result) => {
        if (result.isConfirmed) {
            // 显示删除进度[6](@ref)
            Swal.fire({
                title: '删除中...',
                allowOutsideClick: false,
                didOpen: () => Swal.showLoading()
            });

            fetch('/api/comment', {
                method: 'DELETE',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({'comment_id': commentId})
            })
                .then(response => {
                    if (response.ok) {
                        // 删除成功动画[5,9](@ref)
                        Swal.fire({
                            icon: 'success',
                            title: '评论已消失',
                            showConfirmButton: false,
                            timer: 1000
                        }).then(() => {
                            const commentElement = element.closest('.bg-white');
                            commentElement?.classList.add('animate__animated', 'animate__fadeOut');
                            setTimeout(() => commentElement?.remove(), 500);
                        });
                    }
                    return response.json();
                })
                .catch(error => {
                    Swal.fire({
                        icon: 'error',
                        title: '操作失败',
                        text: '服务器连接异常',
                        confirmButtonText: '重试'
                    });
                });
        }
    });
}

// 更新后的字符计数函数
function updateCounter() {
    const textarea = document.getElementById('comment');
    const maxLength = textarea.maxLength;
    const currentLength = textarea.value.length;
    const remainingChars = maxLength - currentLength;

    document.getElementById('remainingChars').textContent = remainingChars;
    document.getElementById('charCount').classList.toggle('hidden', remainingChars > 100);
}