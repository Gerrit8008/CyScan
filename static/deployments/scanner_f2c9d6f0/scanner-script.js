
// Scanner JavaScript
class SecurityScanner {
    constructor(config) {
        this.config = config;
        this.form = document.getElementById('scannerForm');
        this.submitBtn = this.form.querySelector('.scanner-submit-btn');
        this.btnText = this.submitBtn.querySelector('.btn-text');
        this.btnSpinner = this.submitBtn.querySelector('.btn-spinner');
        this.resultsDiv = document.getElementById('scanResults');
        this.errorDiv = document.getElementById('scanError');
        
        this.init();
    }
    
    init() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.setupValidation();
    }
    
    setupValidation() {
        const urlInput = document.getElementById('target_url');
        const emailInput = document.getElementById('contact_email');
        
        urlInput.addEventListener('input', () => {
            this.validateUrl(urlInput);
        });
        
        emailInput.addEventListener('input', () => {
            this.validateEmail(emailInput);
        });
    }
    
    validateUrl(input) {
        const url = input.value;
        if (!url) return true;
        
        try {
            new URL(url);
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            return true;
        } catch {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            return false;
        }
    }
    
    validateEmail(input) {
        const email = input.value;
        if (!email) return true;
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (emailRegex.test(email)) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
            return true;
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            return false;
        }
    }
    
    async handleSubmit(e) {
        e.preventDefault();
        
        if (!this.validateForm()) {
            return;
        }
        
        this.setLoading(true);
        this.hideMessages();
        
        try {
            const formData = new FormData(this.form);
            const scanData = {
                target_url: formData.get('target_url'),
                contact_email: formData.get('contact_email'),
                contact_name: formData.get('contact_name') || '',
                scan_types: formData.getAll('scan_types[]'),
                scanner_uid: this.config.scannerUid
            };
            
            const response = await fetch(this.config.apiBaseUrl + '/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + this.config.apiKey
                },
                body: JSON.stringify(scanData)
            });
            
            const result = await response.json();
            
            if (result.status === 'success') {
                this.showSuccess(result.scan_id);
            } else {
                this.showError(result.message || 'Scan failed. Please try again.');
            }
            
        } catch (error) {
            console.error('Scan error:', error);
            this.showError('Network error. Please check your connection and try again.');
        } finally {
            this.setLoading(false);
        }
    }
    
    validateForm() {
        const urlInput = document.getElementById('target_url');
        const emailInput = document.getElementById('contact_email');
        
        let isValid = true;
        
        if (!this.validateUrl(urlInput)) {
            isValid = false;
        }
        
        if (!this.validateEmail(emailInput)) {
            isValid = false;
        }
        
        if (!urlInput.value.trim()) {
            urlInput.classList.add('is-invalid');
            isValid = false;
        }
        
        if (!emailInput.value.trim()) {
            emailInput.classList.add('is-invalid');
            isValid = false;
        }
        
        return isValid;
    }
    
    setLoading(loading) {
        this.submitBtn.disabled = loading;
        
        if (loading) {
            this.btnText.classList.add('d-none');
            this.btnSpinner.classList.remove('d-none');
        } else {
            this.btnText.classList.remove('d-none');
            this.btnSpinner.classList.add('d-none');
        }
    }
    
    hideMessages() {
        this.resultsDiv.classList.add('d-none');
        this.errorDiv.classList.add('d-none');
    }
    
    showSuccess(scanId) {
        document.getElementById('scanIdDisplay').textContent = scanId;
        this.resultsDiv.classList.remove('d-none');
        this.form.reset();
        
        // Clear validation classes
        this.form.querySelectorAll('.is-valid, .is-invalid').forEach(el => {
            el.classList.remove('is-valid', 'is-invalid');
        });
    }
    
    showError(message) {
        document.getElementById('errorMessage').textContent = message;
        this.errorDiv.classList.remove('d-none');
    }
}

// Initialize scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    if (window.ScannerConfig) {
        new SecurityScanner(window.ScannerConfig);
    }
});

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityScanner;
}
        