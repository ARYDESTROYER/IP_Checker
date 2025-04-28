// session_timer.js
(function () {
  // Utility for event-based cross-page timer
  function SessionTimer(options) {
    this.timeLeft = options.timeLeft || 0;
    this.timeout = options.timeout || 0;
    this.displayElem = options.displayElem;
    this.warningThreshold = options.warningThreshold || 60; // seconds
    this.warningShown = false;
    this.warningElem = null;
    this.expiredCallback = options.onExpired || function () {};
    this.init();
  }

  SessionTimer.prototype.formatTime = function (secs) {
    var m = Math.floor(secs / 60);
    var s = secs % 60;
    return m + ' min ' + (s < 10 ? '0' : '') + s + ' sec';
  };

  SessionTimer.prototype.showWarning = function () {
    if (!this.warningElem) {
      var warning = document.createElement('div');
      warning.className = 'alert alert-warning text-center fixed-top';
      warning.id = 'timeoutWarning';
      warning.style.zIndex = 2000;
      warning.textContent = 'Warning: Your session will expire in 1 minute!';
      document.body.appendChild(warning);
      this.warningElem = warning;
    }
  };

  SessionTimer.prototype.hideWarning = function () {
    if (this.warningElem) {
      this.warningElem.remove();
      this.warningElem = null;
    }
  };

  SessionTimer.prototype.updateDisplay = function () {
    if (this.displayElem) {
      this.displayElem.textContent = this.timeLeft > 0 ? this.formatTime(this.timeLeft) : 'Expired';
    }
  };

  SessionTimer.prototype.tick = function () {
    var self = this;
    if (self.timeLeft > 0) {
      self.timeLeft -= 1;
      if (self.timeLeft === self.warningThreshold && !self.warningShown) {
        self.showWarning();
        self.warningShown = true;
      }
      if (self.timeLeft === 0) {
        self.hideWarning();
        self.expiredCallback();
      }
      self.updateDisplay();
      window.localStorage.setItem('session_time_left', self.timeLeft);
    }
  };

  SessionTimer.prototype.init = function () {
    var self = this;
    // Cross-tab: sync timer
    var stored = window.localStorage.getItem('session_time_left');
    if (stored !== null && !isNaN(parseInt(stored))) {
      self.timeLeft = parseInt(stored);
    }
    self.updateDisplay();
    setInterval(function () {
      self.tick();
    }, 1000);
    window.addEventListener('storage', function (e) {
      if (e.key === 'session_time_left') {
        var val = parseInt(e.newValue);
        if (!isNaN(val)) {
          self.timeLeft = val;
          self.updateDisplay();
        }
      }
    });
  };

  // Attach globally
  window.SessionTimer = SessionTimer;
})();
