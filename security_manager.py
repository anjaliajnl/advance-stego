"""
Security Manager for StegoSecure.
Handles Brute-Force protection and optionally alerts via plyer.
"""
import time
from plyer import notification
from config import MAX_FAILED_ATTEMPTS, LOCKOUT_TIME_SECONDS
from logger import main_logger

class SecurityManager:
    def __init__(self):
        self.failed_attempts = 0
        self.lockout_until = 0

    def record_failed_attempt(self):
        """Records a failed decoding attempt and triggers lockout if necessary."""
        self.failed_attempts += 1
        main_logger.warning(f"Failed decoding attempt logged. Total: {self.failed_attempts}")
        
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS:
            self.lockout_until = time.time() + LOCKOUT_TIME_SECONDS
            main_logger.critical(f"Max failed attempts reached! System locked out for {LOCKOUT_TIME_SECONDS}s.")
            self._trigger_alert()
            
    def record_success(self):
        """Resets the failed attempts counter on successful decode."""
        if self.failed_attempts > 0:
            main_logger.info("Successful decode. Resetting failed attempts counter.")
            self.failed_attempts = 0
            self.lockout_until = 0

    def is_locked_out(self) -> bool:
        """Checks if the system is currently locked out."""
        if time.time() < self.lockout_until:
            remaining = int(self.lockout_until - time.time())
            main_logger.warning(f"Access denied. Lockout active for {remaining} more seconds.")
            return True
        
        # If time has passed, reset counter to give them another try gracefully
        if self.lockout_until > 0 and time.time() >= self.lockout_until:
            self.failed_attempts = 0
            self.lockout_until = 0
            
        return False
        
    def _trigger_alert(self):
        """Triggers a desktop notification for suspicious activity."""
        try:
            notification.notify(
                title="StegoSecure Security Alert",
                message=f"Multiple failed decode attempts detected. Possible brute-force attack.",
                app_name="StegoSecure",
                timeout=5
            )
        except Exception as e:
            main_logger.error(f"Failed to send desktop notification: {str(e)}")

# Global instance
security_manager = SecurityManager()
