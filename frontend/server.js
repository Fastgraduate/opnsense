import express from 'express'
import axios from 'axios'
import https from 'https'
import cors from 'cors'
import dotenv from 'dotenv'
import process from 'process'

dotenv.config()

const app = express()

app.use(cors())
app.use(express.json())

const httpsAgent = new https.Agent({
  rejectUnauthorized: false,
})

const api = axios.create({
  baseURL: process.env.OPNSENSE_URL,
  httpsAgent,
  auth: {
    username: process.env.OPNSENSE_API_KEY,
    password: process.env.OPNSENSE_API_SECRET,
  },
  timeout: 10000,
})

async function applyFirewallChanges() {
  await api.post('/api/firewall/filter_base/apply')
}

/**
 * 공통 에러 응답 함수
 */
function handleApiError(res, error, message) {
  console.error(message, error.response?.data || error.message)

  res.status(error.response?.status || 500).json({
    message,
    error: error.response?.data || error.message,
  })
}

/**
 * 서버 상태 확인용
 */
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    message: 'Backend server is running',
  })
})

/**
 * OPNsense 펌웨어/제품 상태
 */
app.get('/api/opnsense/status', async (req, res) => {
  try {
    const response = await api.get('/api/core/firmware/status')
    res.json(response.data)
  } catch (error) {
    handleApiError(res, error, 'Failed to fetch OPNsense status')
  }
})

/**
 * 방화벽 자동 생성 규칙 조회
 */
app.get('/api/opnsense/rules', async (req, res) => {
  try {
    const response = await api.get('/api/firewall/filter/searchRule')
    res.json(response.data)
  } catch (error) {
    handleApiError(res, error, 'Failed to fetch firewall rules')
  }
})

/**
 * 방화벽 규칙 추가
 */
app.post('/api/opnsense/rules', async (req, res) => {
  try {
    const {
      description,
      action = 'pass',
      interface: ruleInterface = 'lan',
      direction = 'in',
      protocol = 'TCP',
      sourceNet = 'any',
      sourcePort = '',
      destinationNet = 'any',
      destinationPort = '',
      enabled = '1',
      quick = '1',
      log = false,
    } = req.body

    const payload = {
      rule: {
        enabled,
        quick,
        action,
        interface: ruleInterface,
        direction,
        ipprotocol: 'inet',
        protocol,
        source_net: sourceNet,
        source_port: sourcePort,
        destination_net: destinationNet,
        destination_port: destinationPort,
        description: description || 'API rule',
        log: log ? '1' : '0',
      },
    }

    const addResponse = await api.post('/api/firewall/filter/addRule', payload)

    try {
      await applyFirewallChanges()
    } catch (applyError) {
      console.error(
        'apply error:',
        applyError.response?.data || applyError.message,
      )
    }

    res.json({
      message: 'Rule added successfully',
      result: addResponse.data,
    })
  } catch (error) {
    handleApiError(res, error, 'Failed to add firewall rule')
  }
})

/**
 * 방화벽 규칙 삭제
 */
app.delete('/api/opnsense/rules/:uuid', async (req, res) => {
  try {
    const { uuid } = req.params

    const delResponse = await api.post(`/api/firewall/filter/delRule/${uuid}`)

    try {
      await applyFirewallChanges()
    } catch (applyError) {
      console.error(
        'apply error:',
        applyError.response?.data || applyError.message,
      )
    }

    res.json({
      message: 'Rule deleted successfully',
      result: delResponse.data,
    })
  } catch (error) {
    handleApiError(res, error, 'Failed to delete firewall rule')
  }
})

/**
 * 시스템 정보 조회
 * CPU / 메모리 / 호스트명 / 업타임 등
 */
app.get('/api/opnsense/system', async (req, res) => {
  try {
    const response = await api.get('/api/diagnostics/system/systemInformation')
    res.json(response.data)
  } catch (error) {
    handleApiError(res, error, 'Failed to fetch system information')
  }
})

/**
 * 인터페이스 정보 조회
 * WAN / LAN / 기타 인터페이스 상태
 */
app.get('/api/opnsense/interfaces', async (req, res) => {
  try {
    const response = await api.get('/api/interfaces/overview/export')
    res.json(response.data)
  } catch (error) {
    handleApiError(res, error, 'Failed to fetch interfaces information')
  }
})

/**
 * 서비스 상태 조회
 * packet filter, webgui 등
 */
app.get('/api/opnsense/services', async (req, res) => {
  try {
    const response = await api.get('/api/core/service/search')
    res.json(response.data)
  } catch (error) {
    handleApiError(res, error, 'Failed to fetch services information')
  }
})

/**
 * 인터페이스 트래픽 조회
 * 실시간/통계용
 */
app.get('/api/opnsense/traffic', async (req, res) => {
  try {
    const response = await api.get(
      '/api/diagnostics/interface/getInterfaceTraffic',
    )
    res.json(response.data)
  } catch (error) {
    handleApiError(res, error, 'Failed to fetch interface traffic')
  }
})

/**
 * 대시보드 한번에 조회
 * 프론트에서 여러 번 fetch하기 귀찮으면 이거 하나만 호출해도 됨
 */
app.get('/api/opnsense/dashboard', async (req, res) => {
  try {
    const [
      statusRes,
      rulesRes,
      systemRes,
      interfacesRes,
      servicesRes,
      trafficRes,
    ] = await Promise.allSettled([
      api.get('/api/core/firmware/status'),
      api.get('/api/firewall/filter/searchRule'),
      api.get('/api/diagnostics/system/systemInformation'),
      api.get('/api/interfaces/overview/export'),
      api.get('/api/core/service/search'),
      api.get('/api/diagnostics/interface/getInterfaceTraffic'),
    ])

    res.json({
      status: statusRes.status === 'fulfilled' ? statusRes.value.data : null,
      rules: rulesRes.status === 'fulfilled' ? rulesRes.value.data : null,
      system: systemRes.status === 'fulfilled' ? systemRes.value.data : null,
      interfaces:
        interfacesRes.status === 'fulfilled' ? interfacesRes.value.data : null,
      services:
        servicesRes.status === 'fulfilled' ? servicesRes.value.data : null,
      traffic: trafficRes.status === 'fulfilled' ? trafficRes.value.data : null,
      errors: {
        status:
          statusRes.status === 'rejected'
            ? statusRes.reason.response?.data || statusRes.reason.message
            : null,
        rules:
          rulesRes.status === 'rejected'
            ? rulesRes.reason.response?.data || rulesRes.reason.message
            : null,
        system:
          systemRes.status === 'rejected'
            ? systemRes.reason.response?.data || systemRes.reason.message
            : null,
        interfaces:
          interfacesRes.status === 'rejected'
            ? interfacesRes.reason.response?.data ||
              interfacesRes.reason.message
            : null,
        services:
          servicesRes.status === 'rejected'
            ? servicesRes.reason.response?.data || servicesRes.reason.message
            : null,
        traffic:
          trafficRes.status === 'rejected'
            ? trafficRes.reason.response?.data || trafficRes.reason.message
            : null,
      },
    })
  } catch (error) {
    handleApiError(res, error, 'Failed to fetch dashboard information')
  }
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
