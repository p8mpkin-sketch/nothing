// ============================================================
// DOM XSS 漏洞测试文件 - app.js
// 包含多个真实可利用的 DOM XSS 漏洞，用于安全插件测试
// ============================================================

// 漏洞1: location.hash 直接赋值给 innerHTML，无任何过滤
// POC: http://localhost/test/#<img src=x onerror=alert(1)>
function renderFromHash() {
    var hash = location.hash.slice(1);
    document.getElementById('output1').innerHTML = decodeURIComponent(hash);
}

// 漏洞2: URLSearchParams 读取 name 参数直接写入 innerHTML
// POC: http://localhost/test/?name=<script>alert(2)</script>
function renderFromQuery() {
    var params = new URLSearchParams(location.search);
    var name = params.get('name');
    if (name) {
        document.getElementById('output2').innerHTML = '欢迎你，' + name;
    }
}

// 漏洞3: URL 参数通过 document.write 输出
// POC: http://localhost/test/?msg=<img src=x onerror=alert(3)>
function renderViaDocWrite() {
    var params = new URLSearchParams(location.search);
    var msg = params.get('msg');
    if (msg) {
        var container = document.getElementById('output3');
        container.innerHTML = '';
        // 使用 document.write 写入用户输入
        var iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        document.body.appendChild(iframe);
        iframe.contentDocument.write('<div>' + msg + '</div>');
        container.textContent = '已通过 document.write 渲染: ' + msg;
        // 直接 document.write 到主文档（更危险）
        // document.write(msg);
    }
}

// 漏洞4: eval() 直接执行用户输入的字符串
// source: document.getElementById('evalInput').value
// sink: eval(input)
// POC: 在输入框输入 alert('XSS') 后点击执行
function runEval() {
    var input = document.getElementById('evalInput').value;
    try {
        var result = eval(input);  // 直接 eval 用户输入，无任何过滤
        document.getElementById('output4').textContent = '结果: ' + result;
    } catch(e) {
        document.getElementById('output4').textContent = '错误: ' + e.message;
    }
}

// 漏洞4b: URL参数也可触发 eval
// POC: http://localhost:8888/?expr=alert('XSS4b')
(function() {
    var params = new URLSearchParams(location.search);
    var expr = params.get('expr');
    if (expr) {
        eval(expr);  // URL参数直接 eval，攻击者完全可控
    }
})();

// 漏洞5: 模拟 jQuery .html() 注入（原生实现）
// POC: http://localhost/test/?html=<img src=x onerror=alert(5)>
function renderViaHtml() {
    var params = new URLSearchParams(location.search);
    var html = params.get('html');
    if (html) {
        // 模拟 jQuery $(selector).html(userInput)
        var el = document.getElementById('output5');
        el.innerHTML = html;  // 等价于 jQuery .html()，直接注入
    }
}

// 漏洞6: postMessage 数据直接写入 DOM
// POC: 在控制台执行 window.postMessage('<img src=x onerror=alert(6)>', '*')
window.addEventListener('message', function(event) {
    // 未验证 origin，直接使用 event.data
    var output = document.getElementById('output1');
    if (event.data && typeof event.data === 'string') {
        output.innerHTML = output.innerHTML + '<br>消息: ' + event.data;
    }
});

// 漏洞7: document.referrer 写入 innerHTML
// source: document.referrer（攻击者可通过恶意页面跳转控制）
// sink: element.innerHTML
// POC: 从包含 <img src=x onerror=alert(7)> 的恶意页面跳转到此页
function renderReferrer() {
    if (document.referrer) {
        var info = document.createElement('div');
        // 直接将 referrer 写入 innerHTML，无任何过滤
        info.innerHTML = '来自: ' + document.referrer;
        document.body.appendChild(info);
    }
}

// 漏洞8: hash change 事件监听，动态更新内容
window.addEventListener('hashchange', function() {
    var hash = decodeURIComponent(location.hash.slice(1));
    // 直接将 hash 内容插入 DOM
    document.getElementById('output1').innerHTML = hash;
});

// 页面加载时执行所有漏洞函数
window.onload = function() {
    renderFromHash();
    renderFromQuery();
    renderViaDocWrite();
    renderViaHtml();
    renderReferrer();
};
