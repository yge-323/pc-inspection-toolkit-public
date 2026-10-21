"""Reviewed bilingual display text for the built-in listener findings.

Tuple order is fixed: simplified Chinese first, English second. Rule identity,
severity, port/protocol, evidence, and source references remain in their source
fields and are intentionally not duplicated here.
"""
from __future__ import annotations

LISTENER_FINDINGS: dict[str, dict[str, tuple[str, str]]] = {
    "LISTENER_TCP_21_REVIEW": {
        "title": ("TCP 21 非回环监听：核实 FTP 服务", "TCP 21 non-loopback listener: verify the FTP service"),
        "impact": ("21 是常见 FTP 端口候选；不能确认明文口令或匿名访问是否启用。", "Port 21 is commonly associated with FTP; this observation cannot confirm whether plaintext passwords or anonymous access are enabled."),
        "recommendation": ("核对进程与 FTP 实现/版本、匿名访问、TLS 与业务依赖。确认不需要后在维护窗口停用或限制边界。", "Verify the process and FTP implementation/version, anonymous access, TLS, and business dependencies. If the service is confirmed unnecessary, disable it or restrict its exposure during a maintenance window."),
        "rollback": ("恢复原服务状态与配置并验证传输业务。", "Restore the original service state and configuration, then verify the file-transfer workflow."),
        "verification_checkpoint": ("复采监听并由负责人验证批准的文件传输路径。", "Recollect listener evidence and have the owner verify the approved file-transfer path."),
    },
    "LISTENER_TCP_23_REVIEW": {
        "title": ("TCP 23 非回环监听：核实 Telnet 管理服务", "TCP 23 non-loopback listener: verify the Telnet management service"),
        "impact": ("23 是常见 Telnet 服务端口候选；该监听事实不能确认协议实现、明文认证或网络可达性。", "Port 23 is commonly associated with Telnet; the listener observation does not establish the protocol implementation, plaintext authentication, or network reachability."),
        "recommendation": ("核对进程、设备/系统版本、管理用途、访问控制和业务依赖。确认不需要 Telnet 并获得系统负责人批准后，按该产品支持流程停用服务或限制管理边界；未知设备不得套用通用命令。", "Verify the process, device/OS version, management purpose, access controls, and business dependencies. Only after Telnet is confirmed unnecessary and the system owner approves, disable the service or restrict the management boundary using the product's supported procedure. Do not apply generic commands to an unidentified device."),
        "rollback": ("变更前记录原服务状态和配置；维护访问受影响时，按产品支持流程恢复原状态并验证管理通道。", "Record the original service state and configuration before any change. If maintenance access is affected, restore the prior state using the product's supported procedure and verify the management channel."),
        "verification_checkpoint": ("复采监听并验证批准的管理路径、认证策略和业务状态。", "Recollect listener evidence and verify the approved management path, authentication policy, and service state."),
    },
    "LISTENER_TCP_135_REVIEW": {
        "title": ("TCP 135 非回环监听：核实 Windows RPC 端点映射", "TCP 135 non-loopback listener: verify Windows RPC endpoint mapping"),
        "impact": ("135 常用于 Windows RPC；监听不等于已暴露到不可信网络。", "Port 135 is commonly used by Windows RPC; a listener does not by itself mean it is exposed to an untrusted network."),
        "recommendation": ("确认主机角色、防火墙与业务依赖；非必要勿对不可信网络开放。", "Verify the host role, firewall, and business dependencies. Do not expose it to untrusted networks unless required."),
        "rollback": ("恢复防火墙/服务变更前状态并验证域或应用功能。", "Restore the pre-change firewall/service state and verify domain or application functionality."),
        "verification_checkpoint": ("复采监听与防火墙，确认暴露边界符合批准模型。", "Recollect listener and firewall evidence and confirm that the exposure boundary matches the approved model."),
    },
    "LISTENER_TCP_445_REVIEW": {
        "title": ("TCP 445 非回环监听：核实 SMB 文件共享", "TCP 445 non-loopback listener: verify SMB file sharing"),
        "impact": ("445 是常见 SMB 端口；需结合共享权限与防火墙判断风险，不能仅凭端口定性。", "Port 445 is commonly used by SMB. Assess risk together with share permissions and firewall rules; the port alone is not enough to characterize risk."),
        "recommendation": ("核对共享列表、权限、SMBv1 状态与网络边界；按单位策略收敛。", "Review the share list, permissions, SMBv1 state, and network boundary; restrict access in accordance with organizational policy."),
        "rollback": ("恢复共享/防火墙配置并验证文件访问。", "Restore the share/firewall configuration and verify file access."),
        "verification_checkpoint": ("复采监听、共享与防火墙证据。", "Recollect listener, share, and firewall evidence."),
    },
    "LISTENER_TCP_1433_REVIEW": {
        "title": ("TCP 1433 非回环监听：核实 SQL Server", "TCP 1433 non-loopback listener: verify SQL Server"),
        "impact": ("1433 是常见 SQL Server 端口候选；不能确认实例身份或认证强度。", "Port 1433 is commonly associated with SQL Server; the observation cannot establish the instance identity or authentication strength."),
        "recommendation": ("核对进程、实例、认证与防火墙；无必要时限制为应用所需来源。", "Verify the process, instance, authentication, and firewall. If broader access is unnecessary, restrict it to the sources required by the application."),
        "rollback": ("恢复监听/防火墙配置并验证应用连接。", "Restore the listener/firewall configuration and verify application connectivity."),
        "verification_checkpoint": ("复采监听并由 DBA/应用负责人验证。", "Recollect listener evidence and have the DBA or application owner verify it."),
    },
    "LISTENER_TCP_1521_REVIEW": {
        "title": ("TCP 1521 非回环监听：核实 Oracle Listener", "TCP 1521 non-loopback listener: verify the Oracle listener"),
        "impact": ("1521 是常见 Oracle Listener 端口候选。", "Port 1521 is commonly associated with the Oracle listener."),
        "recommendation": ("核对 listener 配置、valid node checking、防火墙与业务客户端；变更须 DBA 批准。", "Review the listener configuration, valid node checking, firewall, and application clients. Changes require DBA approval."),
        "rollback": ("恢复 listener/sqlnet 备份并验证连接。", "Restore the listener/sqlnet backups and verify connectivity."),
        "verification_checkpoint": ("复采监听与配置摘要，DBA 验证授权客户端。", "Recollect listener evidence and a configuration summary; have the DBA verify authorized clients."),
    },
    "LISTENER_TCP_2375_REVIEW": {
        "title": ("TCP 2375 非回环监听：核实远程管理接口", "TCP 2375 non-loopback listener: verify the remote management interface"),
        "impact": ("2375 是常见 Docker Engine 未加密远程 API 候选端口；端口本身不能确认 Docker、认证状态、网络可达性或 root 权限。", "Port 2375 is commonly associated with the unencrypted Docker Engine remote API. The port alone cannot establish that Docker is present, the authentication state, network reachability, or root privileges."),
        "recommendation": ("前置核查：确认实际进程、启动参数、Docker Engine 版本、TLS/认证配置、防火墙和路由边界，并核实业务是否需要远程管理。取得业务负责人批准和维护窗口后，关闭不必要的远程管理，或按 Docker 官方建议选用 SSH 或正确配置的双向 TLS；不要仅凭端口执行停服或改配置。", "Before acting, verify the actual process, startup arguments, Docker Engine version, TLS/authentication configuration, firewall and routing boundaries, and whether the business requires remote management. After approval from the business owner and during a maintenance window, disable remote management if it is unnecessary, or follow Docker's guidance to use SSH or correctly configured mutual TLS. Do not stop a service or change configuration based on the port alone."),
        "rollback": ("变更前保存原配置和启动方式；若获批变更影响管理或业务连接，在维护窗口恢复备份及原启动参数，再验证管理与业务连接。", "Save the original configuration and startup method before a change. If an approved change disrupts management or business connectivity, restore the backup and original startup arguments during a maintenance window, then verify both management and business connections."),
        "verification_checkpoint": ("复采监听并检查实际进程、TLS/认证、主机防火墙及网络边界；由服务负责人验证获批管理路径和业务健康。", "Recollect listener evidence and check the actual process, TLS/authentication, host firewall, and network boundary. Have the service owner verify the approved management path and business health."),
    },
    "LISTENER_TCP_3306_REVIEW": {
        "title": ("TCP 3306 非回环监听：核实 MySQL/MariaDB", "TCP 3306 non-loopback listener: verify MySQL/MariaDB"),
        "impact": ("3306 是常见 MySQL 端口候选；不能确认绑定、账号或 TLS。", "Port 3306 is commonly associated with MySQL; the observation cannot establish the bind address, accounts, or TLS configuration."),
        "recommendation": ("核对 bind-address、账号来源主机、TLS 与防火墙后，再决定是否收敛。", "Review bind-address, the source hosts allowed for accounts, TLS, and the firewall before deciding whether to restrict access."),
        "rollback": ("恢复 my.cnf 与防火墙备份并验证应用连接。", "Restore the my.cnf and firewall backups and verify application connectivity."),
        "verification_checkpoint": ("复采监听与配置摘要。", "Recollect listener evidence and a configuration summary."),
    },
    "LISTENER_TCP_3389_REVIEW": {
        "title": ("TCP 3389 非回环监听：核实远程桌面", "TCP 3389 non-loopback listener: verify Remote Desktop"),
        "impact": ("3389 是常见 RDP 端口；需结合 NLA、网络边界与账户策略判断。", "Port 3389 is commonly used by RDP; assess it together with NLA, network boundaries, and account policy."),
        "recommendation": ("确认是否需要对外 RDP；优先 VPN/堡垒机，启用 NLA，限制来源。", "Confirm whether externally reachable RDP is required. Prefer a VPN or bastion host, enable NLA, and restrict source addresses."),
        "rollback": ("恢复 RDP/防火墙设置并验证运维通道。", "Restore the RDP/firewall settings and verify the operations access path."),
        "verification_checkpoint": ("复采监听、RDP 与防火墙证据。", "Recollect listener, RDP, and firewall evidence."),
    },
    "LISTENER_TCP_5432_REVIEW": {
        "title": ("TCP 5432 非回环监听：核实 PostgreSQL", "TCP 5432 non-loopback listener: verify PostgreSQL"),
        "impact": ("5432 是常见 PostgreSQL 端口候选。", "Port 5432 is commonly associated with PostgreSQL."),
        "recommendation": ("核对 listen_addresses、pg_hba.conf、TLS 与防火墙后收敛访问。", "Review listen_addresses, pg_hba.conf, TLS, and the firewall before restricting access."),
        "rollback": ("恢复配置备份并验证连接。", "Restore the configuration backup and verify connectivity."),
        "verification_checkpoint": ("复采监听与访问控制摘要。", "Recollect listener evidence and an access-control summary."),
    },
    "LISTENER_TCP_5900_REVIEW": {
        "title": ("TCP 5900 非回环监听：核实 VNC 远程桌面", "TCP 5900 non-loopback listener: verify VNC remote desktop"),
        "impact": ("5900 是常见 VNC 端口候选；不少实现认证较弱。", "Port 5900 is commonly associated with VNC; authentication is weak in many implementations."),
        "recommendation": ("确认业务需要；无必要则停用或限制来源，优先更安全的远程方案。", "Confirm the business need. If unnecessary, disable the service or restrict source addresses; prefer a more secure remote-access method."),
        "rollback": ("恢复原服务状态。", "Restore the original service state."),
        "verification_checkpoint": ("复采监听并验证批准的远程桌面路径。", "Recollect listener evidence and verify the approved remote-desktop path."),
    },
    "LISTENER_TCP_6379_REVIEW": {
        "title": ("TCP 6379 非回环监听：核实 Redis 服务与访问边界", "TCP 6379 non-loopback listener: verify Redis and its access boundary"),
        "impact": ("6379 是常见 Redis 端口候选；监听事实不能确认服务身份、认证、TLS 或网络可达性。", "Port 6379 is commonly associated with Redis; the listener observation cannot establish service identity, authentication, TLS, or network reachability."),
        "recommendation": ("先核对进程、Redis 完整版本、bind/ACL/认证/TLS 配置、客户端来源及防火墙。业务负责人确认不需要远程访问后，再安排维护窗口收敛监听或边界；不得按未知版本套用配置命令。", "First verify the process, full Redis version, bind/ACL/authentication/TLS configuration, client sources, and firewall. Only after the business owner confirms remote access is unnecessary, schedule listener or boundary restrictions for a maintenance window. Do not apply configuration commands for an unknown version."),
        "rollback": ("变更前备份实际生效配置和启动参数；连接或健康检查失败时恢复备份，并验证获批客户端连接。", "Back up the effective configuration and startup arguments before changing them. If connectivity or health checks fail, restore the backup and verify connections from approved clients."),
        "verification_checkpoint": ("复采监听和配置证据，核实版本及认证/TLS设置，并由业务负责人验证授权客户端访问。", "Recollect listener and configuration evidence, verify the version and authentication/TLS settings, and have the business owner validate access from authorized clients."),
    },
    "LISTENER_TCP_7001_REVIEW": {
        "title": ("TCP 7001 非回环监听：核实 WebLogic 管理/服务端口", "TCP 7001 non-loopback listener: verify the WebLogic management/service port"),
        "impact": ("7001 常见于 WebLogic；不能确认控制台是否暴露。", "Port 7001 is commonly used by WebLogic; the observation cannot establish whether its console is exposed."),
        "recommendation": ("核对进程、监听用途与网络边界；管理端口应限制运维来源。", "Verify the process, listener purpose, and network boundary. Restrict management ports to operations sources."),
        "rollback": ("恢复配置并验证应用。", "Restore the configuration and verify the application."),
        "verification_checkpoint": ("复采监听并由中间件管理员验证。", "Recollect listener evidence and have the middleware administrator verify it."),
    },
    "LISTENER_TCP_8009_REVIEW": {
        "title": ("TCP 8009 非回环监听：核实 Tomcat AJP", "TCP 8009 non-loopback listener: verify Tomcat AJP"),
        "impact": ("8009 常见于 Tomcat AJP Connector。", "Port 8009 is commonly used by the Tomcat AJP Connector."),
        "recommendation": ("确认是否仅应对受信反向代理开放；检查 secretRequired 等版本相关设置。", "Confirm whether it should be accessible only to a trusted reverse proxy. Check version-specific settings such as secretRequired."),
        "rollback": ("恢复 server.xml 备份并验证。", "Restore the server.xml backup and verify the service."),
        "verification_checkpoint": ("复采监听与 Connector 配置摘要。", "Recollect listener evidence and a Connector configuration summary."),
    },
    "LISTENER_TCP_8080_REVIEW": {
        "title": ("TCP 8080 非回环监听：核实 HTTP 应用端口", "TCP 8080 non-loopback listener: verify the HTTP application port"),
        "impact": ("8080 常用于应用/代理；需结合进程与是否应对外判断。", "Port 8080 is commonly used by applications or proxies; assess it together with the process and whether external exposure is intended."),
        "recommendation": ("确认进程与业务暴露模型；管理或测试端口勿对不可信网络开放。", "Verify the process and the business exposure model. Do not expose management or test ports to untrusted networks."),
        "rollback": ("恢复原监听/代理配置。", "Restore the original listener/proxy configuration."),
        "verification_checkpoint": ("复采监听并由应用负责人确认。", "Recollect listener evidence and have the application owner confirm it."),
    },
    "LISTENER_TCP_9043_REVIEW": {
        "title": ("TCP 9043 非回环监听：核实 WAS 管理控制台候选端口", "TCP 9043 non-loopback listener: verify whether this is a WAS administration-console port"),
        "impact": ("9043 常见于 WebSphere 管理控制台 HTTPS。", "Port 9043 is commonly used for the WebSphere administration console over HTTPS."),
        "recommendation": ("确认是否管理端口；应限制运维来源并核实认证策略。", "Confirm whether this is a management port. Restrict it to operations sources and verify the authentication policy."),
        "rollback": ("按 WAS 管理员流程恢复。", "Restore the prior state using the WAS administrator's procedure."),
        "verification_checkpoint": ("复采监听并由 WAS 管理员验证。", "Recollect listener evidence and have the WAS administrator verify it."),
    },
    "LISTENER_TCP_9200_REVIEW": {
        "title": ("TCP 9200 非回环监听：核实 Elasticsearch/HTTP API", "TCP 9200 non-loopback listener: verify Elasticsearch/HTTP API"),
        "impact": ("9200 常见于 Elasticsearch HTTP；未认证暴露风险高，但端口不能证明产品与认证状态。", "Port 9200 is commonly used by the Elasticsearch HTTP API. Unauthenticated exposure can be high risk, but the port alone cannot establish the product or authentication state."),
        "recommendation": ("核对进程、安全插件/认证、绑定地址与防火墙；无必要勿对不可信网络开放。", "Verify the process, security plugins/authentication, bind address, and firewall. Do not expose it to untrusted networks unless required."),
        "rollback": ("恢复配置并验证集群健康。", "Restore the configuration and verify cluster health."),
        "verification_checkpoint": ("复采监听与安全配置摘要。", "Recollect listener evidence and a security-configuration summary."),
    },
    "LISTENER_TCP_UDP_11211_REVIEW": {
        "title": ("TCP/UDP 11211 非回环监听：核实 Memcached 服务与访问边界", "TCP/UDP 11211 non-loopback listener: verify Memcached and its access boundary"),
        "impact": ("11211 是常见 Memcached 端口候选；UDP 监听也可能扩大暴露面，但端口不能确认服务身份或可达性。", "Port 11211 is commonly associated with Memcached. A UDP listener may also increase exposure, but the port alone cannot establish service identity or reachability."),
        "recommendation": ("先核对实际进程、Memcached 版本、协议启用项、绑定地址、防火墙和客户端来源。确认业务依赖并取得批准后，在维护窗口关闭不必要的远程或 UDP 访问；不要仅凭端口停止服务。", "First verify the actual process, Memcached version, enabled protocols, bind address, firewall, and client sources. After confirming business dependencies and obtaining approval, disable unnecessary remote or UDP access during a maintenance window. Do not stop the service based on the port alone."),
        "rollback": ("变更前保存配置与启动参数；业务连接失败时恢复备份并验证缓存客户端及应用健康。", "Save the configuration and startup arguments before changing them. If business connectivity fails, restore the backup and verify cache clients and application health."),
        "verification_checkpoint": ("复采 TCP/UDP 监听和边界规则，由服务负责人验证授权客户端访问和应用健康。", "Recollect TCP/UDP listener evidence and boundary rules; have the service owner verify authorized-client access and application health."),
    },
    "LISTENER_TCP_27017_REVIEW": {
        "title": ("TCP 27017 非回环监听：核实 MongoDB", "TCP 27017 non-loopback listener: verify MongoDB"),
        "impact": ("27017 是常见 MongoDB 端口候选；不能确认认证是否启用。", "Port 27017 is commonly associated with MongoDB; the observation cannot establish whether authentication is enabled."),
        "recommendation": ("核对进程、bindIp、认证与网络边界；生产库禁止无认证对不可信网络监听。", "Verify the process, bindIp, authentication, and network boundary. Production databases must not listen on untrusted networks without authentication."),
        "rollback": ("恢复配置并验证应用。", "Restore the configuration and verify the application."),
        "verification_checkpoint": ("复采监听与安全配置摘要。", "Recollect listener evidence and a security-configuration summary."),
    },
}
