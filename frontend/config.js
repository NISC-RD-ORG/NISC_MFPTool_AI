/**
 * MFP Tool API 配置檔案
 * 統一管理所有頁面的API端點配置
 */

window.MFP_CONFIG = {
    // API配置 - 開發環境使用 localhost，生產環境使用正式域名
    API: {
        // 開發環境 (本機測試) - 直接指向後端根路徑
        development: 'http://127.0.0.1:8000',
        // 生產環境 - 包含完整路徑
        production: 'https://ai.nisc.com.tw/mfp_tool/api'
    },
    
    // 其他配置選項
    SETTINGS: {
        // Token 過期時間 (小時)
        tokenExpiryHours: 8,
        // 自動登出前的警告時間 (分鐘)
        autoLogoutWarningMinutes: 30,
        // 預設頁面標題
        defaultTitle: 'MFP Tool Interface'
    }
};

/**
 * 獲取當前環境的API基礎URL
 * 自動檢測環境：如果是 localhost 就使用開發環境，否則使用生產環境
 */
window.getApiBaseUrl = function() {
    const isLocalhost = window.location.hostname === 'localhost' || 
                       window.location.hostname === '127.0.0.1' || 
                       window.location.hostname === '0.0.0.0';
    
    const apiUrl = isLocalhost ? window.MFP_CONFIG.API.development : window.MFP_CONFIG.API.production;
    
    console.log('Environment detected:', isLocalhost ? 'Development' : 'Production');
    console.log('API Base URL:', apiUrl);
    
    return apiUrl;
};

/**
 * 獲取認證標頭
 */
window.getAuthHeaders = function() {
    const token = localStorage.getItem('access_token');
    return {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
};

/**
 * 通用的錯誤處理函數
 */
window.handleApiError = function(error, redirectToLogin = true) {
    console.error('API Error:', error);
    
    if (error.message && error.message.includes('401')) {
        // 未授權錯誤，清除token並重導向到登入頁面
        localStorage.removeItem('access_token');
        localStorage.removeItem('user_info');
        
        if (redirectToLogin) {
            window.location.href = 'login.html';
        }
        return;
    }
    
    // 其他錯誤處理
    return error;
};

/**
 * 登出功能
 */
window.logout = function() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_info');
    window.location.href = 'login.html';
};

// 初始化時輸出配置信息（僅在開發環境）
if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    console.log('MFP_CONFIG loaded:', window.MFP_CONFIG);
}
