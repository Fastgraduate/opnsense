# Global real-time attack notification

- `App.jsx` polls the selected firewall's `/security-alerts` endpoint every 5 seconds even when another page is open.
- The first poll creates a baseline only, so existing historical attacks are not shown as new notifications.
- Newly observed attack IDs are shown as top-right in-app toast notifications.
- Up to four attack notifications are displayed at once and each closes automatically after 8 seconds.
- Clicking a notification navigates directly to the `securityAlerts` page.
- New attacks are also recorded in App Logs as `WARN` entries.
- Switching the selected firewall resets the watcher baseline and clears old notifications.
