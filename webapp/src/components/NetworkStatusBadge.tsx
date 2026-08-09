import { WifiOff } from 'lucide-preact';
import { useEffect, useState } from 'preact/hooks';
import { t } from '@/lib/i18n';
import {
  browserReportsOffline,
  getCurrentNetworkStatus,
  probeNodeWardenService,
  setCurrentNetworkStatus,
  subscribeNetworkStatus,
  type NetworkStatus,
} from '@/lib/network-status';

const STATUS_CHECK_INTERVAL_MS = 30_000;

export default function NetworkStatusBadge() {
  const [status, setStatus] = useState<NetworkStatus>(getCurrentNetworkStatus);

  useEffect(() => {
    let timer = 0;

    const checkService = async () => {
      if (browserReportsOffline()) {
        setCurrentNetworkStatus('offline');
        return;
      }
      await probeNodeWardenService();
    };

    const scheduleNextCheck = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        void checkService().finally(scheduleNextCheck);
      }, STATUS_CHECK_INTERVAL_MS);
    };

    const handleOnline = () => {
      void checkService();
    };
    const handleOffline = () => {
      setCurrentNetworkStatus('offline');
    };
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') void checkService();
    };

    const unsubscribe = subscribeNetworkStatus(setStatus);
    void checkService().finally(scheduleNextCheck);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    window.addEventListener('focus', handleOnline);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      unsubscribe();
      window.clearTimeout(timer);
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      window.removeEventListener('focus', handleOnline);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  if (status !== 'offline') return null;

  const label = t('txt_offline');

  return (
    <span
      className={`network-status-badge ${status}`}
      title={label}
      aria-label={label}
      aria-live="polite"
    >
      <WifiOff size={14} aria-hidden="true" />
      <span className="network-status-label">{label}</span>
    </span>
  );
}
