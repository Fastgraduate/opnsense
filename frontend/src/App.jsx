import { useCanManage } from './auth/AuthContext';
import MyPage from './pages/MyPage';
import { apiFetch as fetch, API_BASE as AUTH_API_BASE } from './auth/api';
import { twc } from "./lib/twc";
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Sidebar from './components/layout/Sidebar';
import AppTopbar from './components/layout/AppTopbar';
import SectionDeckNav from './components/layout/SectionDeckNav';
import AttackToastStack from './components/ui/AttackToastStack';
import { useModal } from './components/ui/modalContext';
import { getSectionForPage } from './navigation/sectionDecks';
import DashboardPage from './pages/DashboardPage';
import FirewallLogIndexPage from './pages/FirewallLogIndexPage';
import FirewallLogSqlSearchPage from './pages/FirewallLogSqlSearchPage';
import FirewallManagerPage from './pages/FirewallManagerPage';
import LogsPage from './pages/LogsPage';
import RulesPage from './pages/RulesPage';
import OpnsenseFirewallLogsPage from './pages/OpnsenseFirewallLogsPage';
import OpnsenseLogOverviewPage from './pages/OpnsenseLogOverviewPage';
import FirewallInterfaceRulesPage from './pages/FirewallInterfaceRulesPage';
import SecurityAlertsPage from './pages/SecurityAlertsPage';
import AutomaticBlockedIpPage from './pages/AutomaticBlockedIpPage';
import BlockedIpListPage from './pages/BlockedIpListPage';
const API_BASE = AUTH_API_BASE;
const TRAFFIC_HISTORY_LIMIT = 20;
const SELECTED_FIREWALL_STORAGE_KEY = 'opnsense:selected-firewall-id';
function App() {
  const canManage = useCanManage();
  const {
    confirm,
    notify
  } = useModal();
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [pageDirection, setPageDirection] = useState('next');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [dashboard, setDashboard] = useState(null);
  const [trafficHistory, setTrafficHistory] = useState([]);
  const [currentInterfaceStats, setCurrentInterfaceStats] = useState([]);
  const [firewalls, setFirewalls] = useState([]);
  const [selectedFirewallId, setSelectedFirewallId] = useState(null);
  const lastTrafficRef = useRef(null);
  const logDedupRef = useRef(new Map());
  const dashboardHadErrorsRef = useRef(false);
  const attackSeenRef = useRef(new Set());
  const attackWatcherReadyRef = useRef(false);
  const attackPollBusyRef = useRef(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [attackToasts, setAttackToasts] = useState([]);
  const [logs, setLogs] = useState([{
    id: 1,
    time: new Date().toLocaleString(),
    level: 'INFO',
    message: '대시보드 초기화 완료'
  }]);
  const [form, setForm] = useState({
    description: '',
    action: 'pass',
    interface: 'lan',
    direction: 'in',
    protocol: 'TCP',
    sourceNet: 'any',
    sourcePort: '',
    destinationNet: 'any',
    destinationPort: '',
    enabled: '1',
    quick: '1',
    log: false
  });
  const selectedFirewall = useMemo(() => firewalls.find(fw => fw.id === selectedFirewallId) || null, [firewalls, selectedFirewallId]);
  const activeSection = useMemo(() => getSectionForPage(currentPage), [currentPage]);
  const navigateToPage = useCallback((nextPage, requestedIndex) => {
    const nextSection = getSectionForPage(nextPage);
    if (nextSection && activeSection?.id === nextSection.id) {
      const currentIndex = activeSection.pages.findIndex(page => page.id === currentPage);
      const nextIndex = Number.isInteger(requestedIndex) ? requestedIndex : nextSection.pages.findIndex(page => page.id === nextPage);
      setPageDirection(nextIndex >= currentIndex ? 'next' : 'prev');
    } else {
      setPageDirection('next');
    }
    setCurrentPage(nextPage);
  }, [activeSection, currentPage]);
  const moveSection = useCallback(step => {
    if (!activeSection) return;
    const currentIndex = Math.max(0, activeSection.pages.findIndex(page => page.id === currentPage));
    const nextIndex = (currentIndex + step + activeSection.pages.length) % activeSection.pages.length;
    setPageDirection(step > 0 ? 'next' : 'prev');
    setCurrentPage(activeSection.pages[nextIndex].id);
  }, [activeSection, currentPage]);
  useEffect(() => {
    if (!activeSection) return undefined;
    const handleSectionKeys = event => {
      const tagName = event.target?.tagName?.toLowerCase();
      if (['input', 'select', 'textarea'].includes(tagName)) return;
      if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
      if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
        event.preventDefault();
        event.stopPropagation();
        moveSection(event.key === 'ArrowLeft' ? -1 : 1);
      }
    };
    window.addEventListener('keydown', handleSectionKeys, {
      passive: false
    });
    return () => window.removeEventListener('keydown', handleSectionKeys);
  }, [activeSection, moveSection]);
  const addLog = useCallback((level, message, options = {}) => {
    const normalizedLevel = String(level || 'INFO').toUpperCase();
    const safeLevel = ['INFO', 'SUCCESS', 'WARN', 'ERROR'].includes(normalizedLevel) ? normalizedLevel : 'INFO';
    const safeMessage = String(message || '').trim() || '내용 없음';
    const dedupeMs = Number(options.dedupeMs || 0);
    const dedupeKey = options.dedupeKey || `${safeLevel}:${safeMessage}`;

    if (dedupeMs > 0) {
      const now = Date.now();
      const previous = logDedupRef.current.get(dedupeKey) || 0;
      if (now - previous < dedupeMs) return;
      logDedupRef.current.set(dedupeKey, now);

      if (logDedupRef.current.size > 200) {
        const cutoff = now - 10 * 60 * 1000;
        for (const [key, timestamp] of logDedupRef.current.entries()) {
          if (timestamp < cutoff) logDedupRef.current.delete(key);
        }
      }
    }

    setLogs(prev => [{
      id: Date.now() + Math.random(),
      time: new Date().toLocaleString(),
      level: safeLevel,
      message: safeMessage
    }, ...prev]);
  }, []);
  const dismissAttackToast = useCallback(toastId => {
    setAttackToasts(previous => previous.filter(item => item.toastId !== toastId));
  }, []);

  const openAttackToast = useCallback(attack => {
    dismissAttackToast(attack.toastId);
    navigateToPage('securityAlerts');
  }, [dismissAttackToast, navigateToPage]);

  useEffect(() => {
    attackSeenRef.current = new Set();
    attackWatcherReadyRef.current = false;
    attackPollBusyRef.current = false;
    setAttackToasts([]);

    if (!selectedFirewallId) return undefined;

    let disposed = false;
    let timerId = null;

    const attackKey = row => String(
      row?.id
      || row?._id
      || [row?.timestamp, row?.source_ip, row?.destination_ip, row?.rule || row?.signature, row?.event_type].join('|')
    );

    const pollAttacks = async () => {
      if (disposed || attackPollBusyRef.current) return;
      attackPollBusyRef.current = true;

      try {
        const response = await fetch(
          `${API_BASE}/api/firewalls/${selectedFirewallId}/security-alerts?minutes=5&size=500&query=&include_all_events=false`,
          { cache: 'no-store' }
        );
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(typeof data?.detail === 'string' ? data.detail : data?.detail?.message || data?.message || `공격 탐지 감시 실패 (${response.status})`);
        }

        if (disposed) return;

        const rows = Array.isArray(data?.rows) ? data.rows : [];
        const nextKeys = rows.map(attackKey);

        // 최초 조회에서는 과거 공격을 대량 알림하지 않되, 방금 들어온 공격(최근 15초)은
        // 앱 로그의 WARN과 우측 상단 알림에서 놓치지 않는다.
        if (!attackWatcherReadyRef.current) {
          const now = Date.now();
          const veryRecent = rows.filter(row => {
            const timestamp = Date.parse(row?.timestamp || '');
            return Number.isFinite(timestamp) && Math.abs(now - timestamp) <= 15000;
          });
          attackSeenRef.current = new Set(nextKeys);
          attackWatcherReadyRef.current = true;

          if (!veryRecent.length) return;

          const created = veryRecent.slice(0, 4).map((row, index) => ({
            ...row,
            toastId: `${attackKey(row)}:${Date.now()}:${index}`
          }));
          setAttackToasts(previous => [...created, ...previous].slice(0, 4));

          veryRecent.forEach(row => {
            const mlDisplay = row?.ml?.detected_class || row?.ml?.prediction || row?.ml?.main_result_display || row?.category || row?.event_type || '공격 이벤트';
            const attackName = String(mlDisplay).split('·')[0].trim();
            const route = `${row?.source_ip || '—'} → ${row?.destination_ip || '—'}`;
            const signature = row?.rule || row?.signature || '';
            addLog('WARN', `공격 탐지: ${attackName} · ${route}${signature ? ` · ${signature}` : ''}`, {
              dedupeKey: `attack:${selectedFirewallId}:${attackKey(row)}`,
              dedupeMs: 10 * 60 * 1000
            });
          });
          return;
        }

        const fresh = rows.filter(row => {
          const key = attackKey(row);
          if (attackSeenRef.current.has(key)) return false;
          attackSeenRef.current.add(key);
          return true;
        });

        // 장시간 실행 시 Set이 무한히 커지지 않도록 현재 조회 범위 + 최근 식별자만 유지한다.
        if (attackSeenRef.current.size > 2500) {
          attackSeenRef.current = new Set(nextKeys);
        }

        if (!fresh.length || disposed) return;

        const created = fresh.slice(0, 4).map((row, index) => ({
          ...row,
          toastId: `${attackKey(row)}:${Date.now()}:${index}`
        }));

        setAttackToasts(previous => [...created, ...previous].slice(0, 4));

        fresh.forEach(row => {
          const mlDisplay = row?.ml?.detected_class || row?.ml?.prediction || row?.ml?.main_result_display || row?.category || row?.event_type || '공격 이벤트';
          const attackName = String(mlDisplay).split('·')[0].trim();
          const route = `${row?.source_ip || '—'} → ${row?.destination_ip || '—'}`;
          const signature = row?.rule || row?.signature || '';
          addLog('WARN', `공격 탐지: ${attackName} · ${route}${signature ? ` · ${signature}` : ''}`, {
            dedupeKey: `attack:${selectedFirewallId}:${attackKey(row)}`,
            dedupeMs: 10 * 60 * 1000
          });
        });
      } catch (watchError) {
        if (!disposed) {
          addLog('ERROR', `실시간 공격 알림 감시 실패: ${watchError.message || watchError}`, {
            dedupeKey: `attack-watch:${selectedFirewallId}:${watchError.message || watchError}`,
            dedupeMs: 60000
          });
        }
      } finally {
        attackPollBusyRef.current = false;
      }
    };

    pollAttacks();
    timerId = window.setInterval(pollAttacks, 5000);

    return () => {
      disposed = true;
      if (timerId) window.clearInterval(timerId);
      attackPollBusyRef.current = false;
    };
  }, [selectedFirewallId, addLog]);

  const parseErrorMessage = (data, fallback) => {
    if (!data) return fallback;
    if (typeof data === 'string') return data;
    if (data.detail?.message) return data.detail.message;
    if (typeof data.detail === 'string') return data.detail;
    if (data.detail?.detail) return data.detail.detail;
    if (data.detail?.error) return data.detail.error;
    if (data.message) return data.message;
    if (data.error) return data.error;
    try {
      return JSON.stringify(data.detail || data);
    } catch {
      return fallback;
    }
  };
  const collectDashboardErrors = data => {
    const blocks = [
      ['상태', data?.status],
      ['룰', data?.rules],
      ['시스템 정보', data?.system],
      ['인터페이스', data?.interfaces],
      ['서비스', data?.services],
      ['트래픽', data?.traffic],
      ['메모리', data?.memory],
      ['디스크', data?.disk],
      ['Alias', data?.aliases]
    ];

    return blocks.flatMap(([label, value]) => {
      const message = value && typeof value === 'object' && !Array.isArray(value) ? value.error : '';
      return message ? [`${label}: ${message}`] : [];
    });
  };

  const logFetchError = (scope, error, dedupeKey) => {
    const message = error?.message || String(error || `${scope} 실패`);
    addLog('ERROR', `${scope}: ${message}`, {
      dedupeKey: dedupeKey || `${scope}:${message}`,
      dedupeMs: 30000
    });
    return message;
  };

  const toNumber = value => {
    if (value == null) return 0;
    if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
    const cleaned = String(value).replace(/[^\d.-]/g, '');
    const num = Number(cleaned);
    return Number.isFinite(num) ? num : 0;
  };
  const normalizeTrafficRows = traffic => {
    if (!traffic) return [];
    if (Array.isArray(traffic)) return traffic;
    if (Array.isArray(traffic?.rows)) return traffic.rows;
    if (Array.isArray(traffic?.interfaces)) return traffic.interfaces;
    if (Array.isArray(traffic?.data)) return traffic.data;
    if (traffic?.statistics && typeof traffic.statistics === 'object') {
      return Object.entries(traffic.statistics).map(([rawKey, value]) => {
        let iface = rawKey;
        if (rawKey.includes('(em0)')) iface = 'em0';else if (rawKey.includes('(em1)')) iface = 'em1';else if (rawKey.includes('(em2)')) iface = 'em2';else if (rawKey.includes('(lo0)')) iface = 'lo0';
        return {
          name: iface,
          rawKey,
          ...(typeof value === 'object' ? value : {
            value
          })
        };
      });
    }
    if (typeof traffic === 'object') {
      return Object.entries(traffic).filter(([key]) => key !== 'error').map(([name, value]) => ({
        name,
        ...(typeof value === 'object' ? value : {
          value
        })
      }));
    }
    return [];
  };
  const extractInterfaceGroupLabel = rawName => {
    if (!rawName) return 'UNKNOWN';
    if (rawName.includes('em0')) return 'WAN';
    if (rawName.includes('em1')) return 'LAN';
    if (rawName.includes('em2')) return 'OPT1';
    if (rawName.includes('lo0')) return 'LOOPBACK';
    return rawName;
  };
  const extractInterfaceCounters = row => {
    const source = row || {};
    const entries = Object.entries(source);
    const findMetric = patterns => {
      for (const [rawKey, rawValue] of entries) {
        const key = String(rawKey).toLowerCase().replace(/[\s_\-:/()[\].]/g, '');
        if (patterns.some(pattern => key.includes(pattern))) {
          return toNumber(rawValue);
        }
      }
      return 0;
    };
    return {
      rxBytes: findMetric(['bytesreceived', 'receivedbytes', 'rxbytes', 'inbytes', 'ibytes', 'bytesin']),
      txBytes: findMetric(['bytestransmitted', 'transmittedbytes', 'txbytes', 'outbytes', 'obytes', 'bytesout', 'sentbytes', 'sendbytes']),
      rxPackets: findMetric(['packetsreceived', 'receivedpackets', 'rxpackets', 'inpackets', 'inpkts', 'ipackets', 'packetsin']),
      txPackets: findMetric(['packetstransmitted', 'transmittedpackets', 'txpackets', 'outpackets', 'outpkts', 'opackets', 'packetsout', 'sentpackets', 'sendpackets']),
      rxErrors: findMetric(['inputerrors', 'rxerrors', 'ierrors']),
      txErrors: findMetric(['outputerrors', 'txerrors', 'oerrors']),
      collisions: findMetric(['collisions', 'colls'])
    };
  };
  const buildCurrentInterfaceStats = rows => {
    const grouped = {};
    rows.forEach((row, index) => {
      const label = extractInterfaceGroupLabel(row?.name || `interface-${index + 1}`);
      const counters = extractInterfaceCounters(row);
      if (!grouped[label]) {
        grouped[label] = {
          id: label,
          label,
          interface: label,
          rxBytes: 0,
          txBytes: 0,
          rxPackets: 0,
          txPackets: 0,
          rxErrors: 0,
          txErrors: 0,
          collisions: 0,
          totalBytes: 0,
          totalPackets: 0
        };
      }
      grouped[label].rxBytes += counters.rxBytes;
      grouped[label].txBytes += counters.txBytes;
      grouped[label].rxPackets += counters.rxPackets;
      grouped[label].txPackets += counters.txPackets;
      grouped[label].rxErrors += counters.rxErrors;
      grouped[label].txErrors += counters.txErrors;
      grouped[label].collisions += counters.collisions;
      grouped[label].totalBytes = grouped[label].rxBytes + grouped[label].txBytes;
      grouped[label].totalPackets = grouped[label].rxPackets + grouped[label].txPackets;
    });
    return Object.values(grouped).filter(item => item.totalBytes > 0 || item.totalPackets > 0);
  };
  const updateTrafficRateHistory = traffic => {
    const rows = normalizeTrafficRows(traffic);
    const currentStats = buildCurrentInterfaceStats(rows);
    setCurrentInterfaceStats(currentStats);
    const now = Date.now();
    const prev = lastTrafficRef.current;
    const currentMap = {};
    currentStats.forEach(item => {
      currentMap[item.interface] = item;
    });
    if (!prev) {
      lastTrafficRef.current = {
        timestamp: now,
        interfaces: currentMap
      };
      return;
    }
    const elapsedSeconds = Math.max((now - prev.timestamp) / 1000, 1);
    const interfaceNames = Array.from(new Set([...Object.keys(prev.interfaces || {}), ...Object.keys(currentMap || {})]));
    const nextPoint = {
      time: new Date(now).toLocaleTimeString(),
      timestamp: now
    };
    interfaceNames.forEach(name => {
      const prevItem = prev.interfaces?.[name];
      const currentItem = currentMap?.[name];
      const prevRx = prevItem?.rxBytes > 0 ? prevItem.rxBytes : prevItem?.rxPackets || 0;
      const currentRx = currentItem?.rxBytes > 0 ? currentItem.rxBytes : currentItem?.rxPackets || 0;
      const prevTx = prevItem?.txBytes > 0 ? prevItem.txBytes : prevItem?.txPackets || 0;
      const currentTx = currentItem?.txBytes > 0 ? currentItem.txBytes : currentItem?.txPackets || 0;
      nextPoint[`rx_${name}`] = Math.max(currentRx - prevRx, 0) / elapsedSeconds;
      nextPoint[`tx_${name}`] = Math.max(currentTx - prevTx, 0) / elapsedSeconds;
    });
    setTrafficHistory(prevHistory => [...prevHistory, nextPoint].slice(-TRAFFIC_HISTORY_LIMIT));
    lastTrafficRef.current = {
      timestamp: now,
      interfaces: currentMap
    };
  };
  const persistSelectedFirewallId = firewallId => {
    if (firewallId === null || firewallId === undefined) {
      window.localStorage.removeItem(SELECTED_FIREWALL_STORAGE_KEY);
      return;
    }
    window.localStorage.setItem(SELECTED_FIREWALL_STORAGE_KEY, String(firewallId));
  };
  const resolvePreferredFirewallId = (list, preferredId = selectedFirewallId) => {
    if (!Array.isArray(list) || list.length === 0) return null;
    const storedId = window.localStorage.getItem(SELECTED_FIREWALL_STORAGE_KEY);
    const candidates = [preferredId, storedId].filter(value => value !== null && value !== undefined && value !== '');
    for (const candidate of candidates) {
      const matched = list.find(fw => String(fw.id) === String(candidate));
      if (matched) return matched.id;
    }
    return list[0].id;
  };
  const fetchFirewalls = async (preferredId = selectedFirewallId) => {
    const res = await fetch(`${API_BASE}/api/firewalls`);
    const data = await res.json();
    if (!res.ok) {
      throw new Error(parseErrorMessage(data, '방화벽 목록 조회 실패'));
    }
    const list = Array.isArray(data) ? data : [];
    const nextSelectedId = resolvePreferredFirewallId(list, preferredId);
    setFirewalls(list);
    setSelectedFirewallId(nextSelectedId);
    persistSelectedFirewallId(nextSelectedId);
    return list;
  };
  const fetchDashboard = async () => {
    if (!selectedFirewallId) return;
    try {
      setLoading(true);
      setError('');
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/dashboard`);
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '대시보드 조회 실패'));
      }

      setDashboard(data);
      updateTrafficRateHistory(data?.traffic);

      const dashboardErrors = collectDashboardErrors(data);
      const firewallName = data?.firewall?.name || selectedFirewall?.name || '방화벽';

      if (dashboardErrors.length > 0) {
        dashboardHadErrorsRef.current = true;
        addLog('ERROR', `${firewallName} 대시보드 일부 조회 실패 · ${dashboardErrors.join(' | ')}`, {
          dedupeKey: `dashboard:${selectedFirewallId}:${dashboardErrors.join('|')}`,
          dedupeMs: 30000
        });
      } else {
        if (dashboardHadErrorsRef.current) {
          addLog('SUCCESS', `${firewallName} OPNsense 연결 복구 및 대시보드 조회 정상화`);
          dashboardHadErrorsRef.current = false;
        } else {
          addLog('INFO', `${firewallName} 대시보드 갱신 완료`, {
            dedupeKey: `dashboard-success:${selectedFirewallId}`,
            dedupeMs: 30000
          });
        }
      }
    } catch (err) {
      const msg = err.message || '대시보드를 불러오지 못했습니다.';
      setError(msg);
      dashboardHadErrorsRef.current = true;
      addLog('ERROR', `${selectedFirewall?.name || '방화벽'} 대시보드 조회 실패: ${msg}`, {
        dedupeKey: `dashboard-http:${selectedFirewallId}:${msg}`,
        dedupeMs: 30000
      });
    } finally {
      setLoading(false);
    }
  };
  const handleSelectFirewall = firewallId => {
    const matched = firewalls.find(fw => String(fw.id) === String(firewallId));
    const nextId = matched?.id ?? null;
    setSelectedFirewallId(nextId);
    persistSelectedFirewallId(nextId);
    setDashboard(null);
    setTrafficHistory([]);
    setCurrentInterfaceStats([]);
    lastTrafficRef.current = null;
    dashboardHadErrorsRef.current = false;
  };
  const handleToggleAutoRefresh = () => {
    setAutoRefresh(prev => !prev);
  };
  useEffect(() => {
    fetchFirewalls().catch(err => {
      const msg = err.message || '방화벽 목록을 불러오지 못했습니다.';
      setError(msg);
      addLog('ERROR', msg);
    });
  }, []);
  useEffect(() => {
    fetchDashboard();
  }, [selectedFirewallId]);
  useEffect(() => {
    if (currentPage !== 'dashboard') return;
    if (!autoRefresh || !selectedFirewallId) return;
    const interval = setInterval(() => {
      if (document.visibilityState === 'visible') {
        fetchDashboard();
      }
    }, 15000);
    return () => clearInterval(interval);
  }, [currentPage, autoRefresh, selectedFirewallId]);
  const handleChange = e => {
    const {
      name,
      value,
      type,
      checked
    } = e.target;
    setForm(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };
  const resetForm = () => {
    setForm({
      description: '',
      action: 'pass',
      interface: 'lan',
      direction: 'in',
      protocol: 'TCP',
      sourceNet: 'any',
      sourcePort: '',
      destinationNet: 'any',
      destinationPort: '',
      enabled: '1',
      quick: '1',
      log: false
    });
  };
  const onCreateFirewall = async payload => {
    const res = await fetch(`${API_BASE}/api/firewalls`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      const message = parseErrorMessage(data, '방화벽 등록 실패');
      addLog('ERROR', `방화벽 등록 실패: ${message}`);
      throw new Error(message);
    }
    await fetchFirewalls(data.id);
    addLog('SUCCESS', `방화벽 등록 완료: ${data.name}`);
    void notify({
      tone: 'success',
      title: '방화벽 등록 완료',
      message: `${data.name} 연결 정보가 안전하게 저장되었습니다.`
    });
  };
  const onUpdateFirewall = async (firewallId, payload) => {
    const res = await fetch(`${API_BASE}/api/firewalls/${firewallId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const message = parseErrorMessage(data, '방화벽 수정 실패');
      addLog('ERROR', `방화벽 정보 수정 실패: ${message}`);
      throw new Error(message);
    }
    await fetchFirewalls(selectedFirewallId);
    if (selectedFirewallId === firewallId) {
      await fetchDashboard();
    }
    addLog('SUCCESS', `방화벽 정보 수정 완료: ${data.name || firewallId}`);
    void notify({
      tone: 'success',
      title: '연결 정보 수정 완료',
      message: `${data.name || '선택한 방화벽'} 설정을 갱신했습니다.`
    });
    return data;
  };
  const onDeleteFirewall = async firewallId => {
    const firewallName = firewalls.find(item => item.id === firewallId)?.name || `ID ${firewallId}`;
    const accepted = await confirm({
      tone: 'danger',
      title: '방화벽 연결 삭제',
      message: `${firewallName} 연결 정보를 삭제합니다.\n이 작업은 목록에서 해당 연결을 제거합니다.`,
      confirmText: '삭제'
    });
    if (!accepted) return;
    const res = await fetch(`${API_BASE}/api/firewalls/${firewallId}`, {
      method: 'DELETE'
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const message = parseErrorMessage(data, '방화벽 삭제 실패');
      addLog('ERROR', `방화벽 삭제 실패: ${message}`);
      throw new Error(message);
    }
    const deletingSelectedFirewall = String(selectedFirewallId) === String(firewallId);
    if (deletingSelectedFirewall) {
      window.localStorage.removeItem(SELECTED_FIREWALL_STORAGE_KEY);
      setDashboard(null);
      setTrafficHistory([]);
      setCurrentInterfaceStats([]);
      lastTrafficRef.current = null;
    }
    await fetchFirewalls(deletingSelectedFirewall ? null : selectedFirewallId);
    addLog('SUCCESS', `방화벽 삭제 완료: ${firewallName}`);
    void notify({
      tone: 'success',
      title: '삭제 완료',
      message: `${firewallName} 연결을 삭제했습니다.`
    });
  };
  const handleAddRule = async e => {
    e.preventDefault();
    if (!selectedFirewallId) {
      setError('방화벽을 먼저 선택하세요.');
      return;
    }
    try {
      setSubmitting(true);
      setError('');
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/rules`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(form)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '룰 추가 실패'));
      }
      addLog('SUCCESS', `룰 추가 완료: ${form.description || '설명 없음'}`);
      void notify({
        tone: 'success',
        title: '방화벽 룰 추가 완료',
        message: form.description || '새 방화벽 룰이 적용되었습니다.'
      });
      resetForm();
      await fetchDashboard();
      setCurrentPage('rules');
    } catch (err) {
      const msg = err.message || '룰 추가 중 오류';
      setError(msg);
      addLog('ERROR', msg);
    } finally {
      setSubmitting(false);
    }
  };
  const handleDeleteRule = async (uuid, description) => {
    if (!selectedFirewallId || !uuid) return;
    const accepted = await confirm({
      tone: 'danger',
      title: '방화벽 룰 삭제',
      message: description || '설명 없는 룰을 삭제합니다.',
      detail: `Rule UUID: ${uuid}`,
      confirmText: '룰 삭제'
    });
    if (!accepted) return;
    try {
      setError('');
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/rules/${uuid}`, {
        method: 'DELETE'
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '룰 삭제 실패'));
      }
      addLog('SUCCESS', `룰 삭제 완료: ${description || uuid}`);
      void notify({
        tone: 'success',
        title: '룰 삭제 완료',
        message: description || uuid
      });
      await fetchDashboard();
    } catch (err) {
      const msg = err.message || '룰 삭제 오류';
      setError(msg);
      addLog('ERROR', msg);
    }
  };

  const fetchOpnsenseLogs = async filters => {
    if (!selectedFirewallId) {
      const error = new Error('방화벽을 먼저 선택하세요.');
      logFetchError('OPNsense 로그 조회 실패', error);
      throw error;
    }
    try {
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/opnsense-logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(filters)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, 'OPNsense 방화벽 로그 조회 실패'));
      }
      return data;
    } catch (err) {
      logFetchError('OPNsense 로그 조회 실패', err, `opnsense-logs:${selectedFirewallId}:${err?.message}`);
      throw err;
    }
  };
  const fetchFirewallInterfaces = async () => {
    if (!selectedFirewallId) {
      const error = new Error('방화벽을 먼저 선택하세요.');
      logFetchError('인터페이스 목록 조회 실패', error);
      throw error;
    }
    try {
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/interfaces`);
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '인터페이스 목록 조회 실패'));
      }
      return data;
    } catch (err) {
      logFetchError('인터페이스 목록 조회 실패', err, `interfaces:${selectedFirewallId}:${err?.message}`);
      throw err;
    }
  };
  const fetchInterfaceRules = async (interfaceKey = '') => {
    if (!selectedFirewallId) {
      const error = new Error('방화벽을 먼저 선택하세요.');
      logFetchError('인터페이스별 룰 조회 실패', error);
      throw error;
    }
    try {
      const url = interfaceKey ? `${API_BASE}/api/firewalls/${selectedFirewallId}/interface-rules?interface=${encodeURIComponent(interfaceKey)}` : `${API_BASE}/api/firewalls/${selectedFirewallId}/interface-rules`;
      const res = await fetch(url);
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '인터페이스별 룰 조회 실패'));
      }
      return data;
    } catch (err) {
      logFetchError('인터페이스별 룰 조회 실패', err, `interface-rules:${selectedFirewallId}:${interfaceKey}:${err?.message}`);
      throw err;
    }
  };
  const fetchLegacyInterfaceRules = async (interfaceKey = 'lan') => {
    if (!selectedFirewallId) {
      const error = new Error('방화벽을 먼저 선택하세요.');
      logFetchError('OPNsense WebGUI 룰 조회 실패', error);
      throw error;
    }
    try {
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/legacy-interface-rules?interface=${encodeURIComponent(interfaceKey || 'lan')}`);
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, 'OPNsense WebGUI 룰 조회 실패'));
      }
      return data;
    } catch (err) {
      logFetchError('OPNsense WebGUI 룰 조회 실패', err, `legacy-rules:${selectedFirewallId}:${interfaceKey}:${err?.message}`);
      throw err;
    }
  };
  const createInterfaceRule = async payload => {
    if (!selectedFirewallId) {
      const error = new Error('방화벽을 먼저 선택하세요.');
      logFetchError('인터페이스 룰 추가 실패', error);
      throw error;
    }
    try {
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/interface-rules`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '인터페이스 룰 추가 실패'));
      }
      addLog('SUCCESS', `인터페이스 룰 추가 완료: ${payload.description || payload.interface}`);
      return data;
    } catch (err) {
      logFetchError('인터페이스 룰 추가 실패', err);
      throw err;
    }
  };
  const updateInterfaceRule = async (uuid, payload) => {
    if (!selectedFirewallId) {
      const error = new Error('방화벽을 먼저 선택하세요.');
      logFetchError('인터페이스 룰 수정 실패', error);
      throw error;
    }
    try {
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/interface-rules/${uuid}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '인터페이스 룰 수정 실패'));
      }
      addLog('SUCCESS', `인터페이스 룰 수정 완료: ${payload.description || uuid}`);
      return data;
    } catch (err) {
      logFetchError('인터페이스 룰 수정 실패', err);
      throw err;
    }
  };
  const deleteInterfaceRule = async uuid => {
    if (!selectedFirewallId) {
      const error = new Error('방화벽을 먼저 선택하세요.');
      logFetchError('인터페이스 룰 삭제 실패', error);
      throw error;
    }
    try {
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/interface-rules/${uuid}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '인터페이스 룰 삭제 실패'));
      }
      addLog('SUCCESS', `인터페이스 룰 삭제 완료: ${uuid}`);
      return data;
    } catch (err) {
      logFetchError('인터페이스 룰 삭제 실패', err);
      throw err;
    }
  };
  const applyInterfaceRules = async () => {
    if (!selectedFirewallId) {
      const error = new Error('방화벽을 먼저 선택하세요.');
      logFetchError('인터페이스 룰 적용 실패', error);
      throw error;
    }
    try {
      const res = await fetch(`${API_BASE}/api/firewalls/${selectedFirewallId}/interface-rules/apply`, {
        method: 'POST'
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '인터페이스 룰 적용 실패'));
      }
      addLog('SUCCESS', '인터페이스 룰 변경사항 적용 완료');
      return data;
    } catch (err) {
      logFetchError('인터페이스 룰 적용 실패', err);
      throw err;
    }
  };
  const handleAppGlassPointer = useCallback(event => {
    const rect = event.currentTarget.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const x = ((event.clientX - rect.left) / rect.width) * 100;
    const y = ((event.clientY - rect.top) / rect.height) * 100;
    event.currentTarget.style.setProperty('--glass-x', `${Math.max(0, Math.min(100, x))}%`);
    event.currentTarget.style.setProperty('--glass-y', `${Math.max(0, Math.min(100, y))}%`);
  }, []);
  const rules = Array.isArray(dashboard?.rules?.rows) ? dashboard.rules.rows : [];
  const aliasesRaw = dashboard?.aliases;
  const aliases = Array.isArray(aliasesRaw) ? aliasesRaw : Array.isArray(aliasesRaw?.rows) ? aliasesRaw.rows : [];
  return <div className={twc("app-shell relative isolate h-screen overflow-hidden")} onPointerMove={handleAppGlassPointer}>
      <div className={twc("pointer-events-none fixed -left-24 top-16 -z-10 h-80 w-80 rounded-full bg-violet-400/15 blur-3xl animate-ambient-float")} />
      <div className={twc("pointer-events-none fixed -right-24 top-1/3 -z-10 h-96 w-96 rounded-full bg-sky-400/12 blur-3xl animate-ambient-float [animation-delay:-4s]")} />
      <div className={twc("pointer-events-none fixed inset-0 -z-10 opacity-70 [background:radial-gradient(circle_at_var(--glass-x)_var(--glass-y),rgba(139,92,246,.10),rgba(56,189,248,.045)_18%,transparent_34%)] transition-opacity duration-500 dark:opacity-55")} />
      <div className={twc("pointer-events-none fixed bottom-[-14rem] left-[32%] -z-10 h-[28rem] w-[28rem] rounded-full bg-fuchsia-400/8 blur-3xl animate-ambient-float [animation-delay:-7s]")} />

      <Sidebar currentPage={currentPage} setCurrentPage={navigateToPage} mobileOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <AttackToastStack attacks={attackToasts} onOpen={openAttackToast} onDismiss={dismissAttackToast} />

      <div className={twc("relative z-10 flex h-screen min-w-0 flex-1 flex-col overflow-hidden")}>
        <AppTopbar onMyPage={() => navigateToPage('myPage')} currentPage={currentPage} selectedFirewall={selectedFirewall} onOpenSidebar={() => setSidebarOpen(true)} />

      {!canManage && <p className="readonly-banner">조회 전용 계정 · 정책 변경과 IP 차단은 관리자만 실행할 수 있습니다.</p>}
      <main className={twc("content")}>
        {error ? <button type="button" className={twc("error card flex w-full items-center justify-between gap-3 text-left")} onClick={() => notify({
          tone: 'danger',
          title: '요청 처리 오류',
          message: error
        })}>
            <span className={twc("min-w-0 truncate")}>{error}</span>
            <span className={twc("shrink-0 text-xs font-black")}>상세 보기</span>
          </button> : null}

        <div className={twc(`page-stage ${activeSection ? 'section-page-stage' : ''}`)}>
        {activeSection ? <SectionDeckNav section={activeSection} currentPage={currentPage} onMove={moveSection} onSelect={navigateToPage} /> : null}

        <div key={currentPage} className={twc(activeSection ? `section-deck-viewport section-deck-${pageDirection}` : currentPage === 'dashboard' ? 'dashboard-page-frame animate-page-enter' : 'standalone-page-frame animate-page-enter')}>

        {currentPage === 'dashboard' && <DashboardPage product={dashboard?.product || dashboard?.status?.product || null} status={dashboard?.status || null} system={dashboard?.system || null} systemSummary={dashboard?.system_summary || null} interfaces={dashboard?.interfaces || null} services={dashboard?.services || null} traffic={dashboard?.traffic || null} memory={dashboard?.memory || null} memorySummary={dashboard?.memory_summary || null} disk={dashboard?.disk || null} diskSummary={dashboard?.disk_summary || null} rules={rules} aliases={aliases} autoRefresh={autoRefresh} loading={loading} trafficHistory={trafficHistory} currentInterfaceStats={currentInterfaceStats} selectedFirewall={selectedFirewall} onToggleAutoRefresh={handleToggleAutoRefresh} onRefreshDashboard={fetchDashboard} />}

        {currentPage === 'rules' && <RulesPage rules={rules} form={form} setForm={setForm} showAdvanced={showAdvanced} setShowAdvanced={setShowAdvanced} submitting={submitting} handleChange={handleChange} handleAddRule={handleAddRule} handleDeleteRule={handleDeleteRule} resetForm={resetForm} selectedFirewall={selectedFirewall} />}

        {currentPage === 'interfaceRules' && <FirewallInterfaceRulesPage selectedFirewall={selectedFirewall} fetchFirewallInterfaces={fetchFirewallInterfaces} fetchInterfaceRules={fetchInterfaceRules} fetchLegacyInterfaceRules={fetchLegacyInterfaceRules} createInterfaceRule={createInterfaceRule} updateInterfaceRule={updateInterfaceRule} deleteInterfaceRule={deleteInterfaceRule} applyInterfaceRules={applyInterfaceRules} />}


        {currentPage === 'eventLogIndex' && <FirewallLogIndexPage key={selectedFirewallId} selectedFirewall={selectedFirewall} />}

        {currentPage === 'eventLogSqlSearch' && <FirewallLogSqlSearchPage key={selectedFirewallId} selectedFirewall={selectedFirewall} />}

        {currentPage === 'opnsenseLogOverview' && <OpnsenseLogOverviewPage selectedFirewall={selectedFirewall} fetchOpnsenseLogs={fetchOpnsenseLogs} />}

        {currentPage === 'opnsenseLogs' && <OpnsenseFirewallLogsPage selectedFirewall={selectedFirewall} fetchOpnsenseLogs={fetchOpnsenseLogs} onAppLog={addLog} />}

        {currentPage === 'securityAlerts' && <SecurityAlertsPage selectedFirewall={selectedFirewall} onAppLog={addLog} />}

        {currentPage === 'automaticBlockedIps' && <AutomaticBlockedIpPage key={selectedFirewallId} selectedFirewall={selectedFirewall} />}
        {currentPage === 'blockedIps' && <BlockedIpListPage selectedFirewall={selectedFirewall} onAppLog={addLog} />}

        {currentPage === 'firewalls' && <FirewallManagerPage firewalls={firewalls} selectedFirewallId={selectedFirewallId} setSelectedFirewallId={handleSelectFirewall} onCreateFirewall={onCreateFirewall} onUpdateFirewall={onUpdateFirewall} onDeleteFirewall={onDeleteFirewall} />}

        {currentPage === 'myPage' && <MyPage />}
        {currentPage === 'logs' && <LogsPage logs={logs} setLogs={setLogs} />}
        </div>
        </div>
      </main>
      </div>
    </div>;
}
export default App;
