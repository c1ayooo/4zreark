import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import * as THREE from 'three'
import anime from 'animejs'
import * as d3 from 'd3-force'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Loader2, X, RotateCcw } from 'lucide-react'
import { resultApi } from '@/api/results'

// Types
interface GraphNode extends d3.SimulationNodeDatum {
  id: string
  name: string
  type: string
  val: number
  color: string
  data: any
  threeObject?: THREE.Object3D
  x?: number
  y?: number
  z?: number
  vx?: number
  vy?: number
  vz?: number
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  source: string | GraphNode
  target: string | GraphNode
  color?: string
  threeObject?: THREE.Line
}

interface TaskTopologyViewProps {
  taskId: string
  taskName: string
}

export default function TaskTopologyView({ 
  taskId, 
  taskName
}: TaskTopologyViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  const [isLoadingGraph, setIsLoadingGraph] = useState(true)

  // 获取各类数据
  const { data: subdomainsData, isLoading: isLoadingSubdomains } = useQuery({
    queryKey: ['topology-subdomains', taskId],
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'subdomain', pageSize: 1000 }),
    enabled: !!taskId,
  })

  const { data: portsData, isLoading: isLoadingPorts } = useQuery({
    queryKey: ['topology-ports', taskId],
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'port', pageSize: 1000 }),
    enabled: !!taskId,
  })

  const { data: servicesData, isLoading: isLoadingServices } = useQuery({
    queryKey: ['topology-services', taskId],
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'service', pageSize: 1000 }),
    enabled: !!taskId,
  })

  const { data: vulnsData, isLoading: isLoadingVulns } = useQuery({
    queryKey: ['topology-vulns', taskId],
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'vuln', pageSize: 1000 }),
    enabled: !!taskId,
  })

  const { data: sensitiveData, isLoading: isLoadingSensitive } = useQuery({
    queryKey: ['topology-sensitive', taskId],
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'sensitive', pageSize: 1000 }),
    enabled: !!taskId,
  })

  const { data: urlsData, isLoading: isLoadingUrls } = useQuery({
    queryKey: ['topology-urls', taskId],
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'url', pageSize: 1000 }),
    enabled: !!taskId,
  })

  const { data: statsData, isLoading: isLoadingStats } = useQuery({
    queryKey: ['topology-stats', taskId],
    queryFn: () => resultApi.getResultStats(taskId),
    enabled: !!taskId,
  })

  // 检查是否还在加载数据
  const isDataLoading = isLoadingSubdomains || isLoadingPorts || isLoadingServices || 
    isLoadingVulns || isLoadingSensitive || isLoadingUrls || isLoadingStats

  // 从 API 响应中提取数据
  const subdomains = subdomainsData?.data?.list || []
  const ports = portsData?.data?.list || []
  const services = servicesData?.data?.list || []
  const vulns = vulnsData?.data?.list || []
  const urls = urlsData?.data?.list || []
  const sensitiveInfos = sensitiveData?.data?.list || []
  const stats = statsData?.data || {}

  // 调试日志
  useEffect(() => {
    console.log('[Topology] Data loaded:', {
      subdomains: subdomains.length,
      ports: ports.length,
      services: services.length,
      vulns: vulns.length,
      urls: urls.length,
      sensitiveInfos: sensitiveInfos.length,
      stats,
      isDataLoading
    })
  }, [subdomains, ports, services, vulns, urls, sensitiveInfos, stats, isDataLoading])
  
  // Three.js refs
  const sceneRef = useRef<THREE.Scene | null>(null)
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null)
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null)
  const animationFrameRef = useRef<number>()
  const nodesRef = useRef<GraphNode[]>([])
  const linksRef = useRef<GraphLink[]>([])
  const raycasterRef = useRef(new THREE.Raycaster())
  const mouseRef = useRef(new THREE.Vector2())
  const simulationRef = useRef<d3.Simulation<GraphNode, GraphLink> | null>(null)

  // Initialize Three.js
  useEffect(() => {
    if (!containerRef.current) return

    const scene = new THREE.Scene()
    scene.fog = new THREE.FogExp2(0x000000, 0.0015)
    sceneRef.current = scene

    const camera = new THREE.PerspectiveCamera(
      60,
      containerRef.current.clientWidth / containerRef.current.clientHeight,
      0.1,
      2000
    )
    camera.position.z = 400
    cameraRef.current = camera

    const renderer = new THREE.WebGLRenderer({ 
      antialias: true, 
      alpha: true,
      powerPreference: "high-performance"
    })
    renderer.setSize(containerRef.current.clientWidth, containerRef.current.clientHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    containerRef.current.appendChild(renderer.domElement)
    rendererRef.current = renderer

    // Starfield background
    const starGeometry = new THREE.BufferGeometry()
    const starMaterial = new THREE.PointsMaterial({
      color: 0xffffff,
      size: 0.5,
      transparent: true,
      opacity: 0.8,
      sizeAttenuation: true
    })
    
    const starVertices = []
    for(let i = 0; i < 2000; i++) {
      const x = (Math.random() - 0.5) * 2000
      const y = (Math.random() - 0.5) * 2000
      const z = (Math.random() - 0.5) * 2000
      starVertices.push(x, y, z)
    }
    starGeometry.setAttribute('position', new THREE.Float32BufferAttribute(starVertices, 3))
    const stars = new THREE.Points(starGeometry, starMaterial)
    scene.add(stars)

    // Mouse controls
    let isDragging = false
    let isRightDragging = false
    let previousMousePosition = { x: 0, y: 0 }
    let targetRotationX = 0
    let targetRotationY = 0
    let autoRotate = true

    const onMouseDown = (e: MouseEvent) => {
      if (e.button === 0) {
        isDragging = true
      } else if (e.button === 2) {
        isRightDragging = true
      }
      autoRotate = false
      previousMousePosition = { x: e.clientX, y: e.clientY }
      e.preventDefault()
    }

    const onContextMenu = (e: MouseEvent) => {
      e.preventDefault()
    }

    const onMouseMove = (e: MouseEvent) => {
      const rect = renderer.domElement.getBoundingClientRect()
      mouseRef.current.x = ((e.clientX - rect.left) / rect.width) * 2 - 1
      mouseRef.current.y = -((e.clientY - rect.top) / rect.height) * 2 + 1

      if (isDragging) {
        const deltaMove = {
          x: e.clientX - previousMousePosition.x,
          y: e.clientY - previousMousePosition.y
        }
        targetRotationY += deltaMove.x * 0.005
        targetRotationX += deltaMove.y * 0.005
        
        // Rotate camera around center
        const radius = camera.position.length()
        const theta = Math.atan2(camera.position.x, camera.position.z) - deltaMove.x * 0.005
        const phi = Math.acos(camera.position.y / radius)
        const targetPhi = Math.max(0.1, Math.min(Math.PI - 0.1, phi - deltaMove.y * 0.005))
        
        camera.position.x = radius * Math.sin(targetPhi) * Math.sin(theta)
        camera.position.y = radius * Math.cos(targetPhi)
        camera.position.z = radius * Math.sin(targetPhi) * Math.cos(theta)
        
        previousMousePosition = { x: e.clientX, y: e.clientY }
      } else if (isRightDragging) {
        // Right drag for panning
        const deltaMove = {
          x: e.clientX - previousMousePosition.x,
          y: e.clientY - previousMousePosition.y
        }
        camera.position.x -= deltaMove.x * 0.5
        camera.position.y += deltaMove.y * 0.5
        previousMousePosition = { x: e.clientX, y: e.clientY }
      }
    }

    const onMouseUp = () => {
      isDragging = false
      isRightDragging = false
      setTimeout(() => { autoRotate = true }, 3000)
    }

    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      camera.position.z = Math.max(100, Math.min(800, camera.position.z + e.deltaY * 0.5))
    }

    const onClick = () => {
      if (isDragging) return
      raycasterRef.current.setFromCamera(mouseRef.current, camera)
      const intersects = raycasterRef.current.intersectObjects(scene.children, true)
      
      for (const intersect of intersects) {
        const node = nodesRef.current.find(n => n.threeObject === intersect.object || n.threeObject?.children.includes(intersect.object as THREE.Object3D))
        if (node) {
          setSelectedNode(node)
          flyToNode(node)
          return
        }
      }
    }

    renderer.domElement.addEventListener('mousedown', onMouseDown)
    renderer.domElement.addEventListener('mousemove', onMouseMove)
    renderer.domElement.addEventListener('mouseup', onMouseUp)
    renderer.domElement.addEventListener('mouseleave', onMouseUp)
    renderer.domElement.addEventListener('wheel', onWheel, { passive: false })
    renderer.domElement.addEventListener('click', onClick)
    renderer.domElement.addEventListener('contextmenu', onContextMenu)

    // Animation loop
    let rotationAngle = 0
    const animate = () => {
      animationFrameRef.current = requestAnimationFrame(animate)
      
      if (autoRotate && !isDragging) {
        rotationAngle += 0.001
        camera.position.x = Math.sin(rotationAngle) * camera.position.z * 0.3
        camera.position.y = Math.cos(rotationAngle * 0.5) * 50
      }
      
      camera.lookAt(0, 0, 0)
      renderer.render(scene, camera)
    }
    animate()

    // Resize handler with ResizeObserver
    const handleResize = () => {
      if (!containerRef.current) return
      const width = containerRef.current.clientWidth
      const height = containerRef.current.clientHeight
      if (width === 0 || height === 0) return
      
      camera.aspect = width / height
      camera.updateProjectionMatrix()
      renderer.setSize(width, height)
    }
    
    // Use ResizeObserver for better resize detection
    const resizeObserver = new ResizeObserver(handleResize)
    if (containerRef.current) {
      resizeObserver.observe(containerRef.current)
    }
    window.addEventListener('resize', handleResize)
    
    // Initial resize after a short delay to ensure container has size
    setTimeout(handleResize, 100)

    return () => {
      resizeObserver.disconnect()
      window.removeEventListener('resize', handleResize)
      renderer.domElement.removeEventListener('mousedown', onMouseDown)
      renderer.domElement.removeEventListener('mousemove', onMouseMove)
      renderer.domElement.removeEventListener('mouseup', onMouseUp)
      renderer.domElement.removeEventListener('mouseleave', onMouseUp)
      renderer.domElement.removeEventListener('wheel', onWheel)
      renderer.domElement.removeEventListener('click', onClick)
      renderer.domElement.removeEventListener('contextmenu', onContextMenu)
      if (animationFrameRef.current) cancelAnimationFrame(animationFrameRef.current)
      renderer.dispose()
      if (containerRef.current?.contains(renderer.domElement)) {
        containerRef.current.removeChild(renderer.domElement)
      }
      if (simulationRef.current) simulationRef.current.stop()
    }
  }, [])

  // Build graph from scan results
  useEffect(() => {
    if (!sceneRef.current) return
    
    // 等待数据加载完成
    if (isDataLoading) {
      console.log('[Topology] Still loading data, skipping graph build')
      return
    }

    // 检查是否有数据
    const hasData = subdomains.length > 0 || ports.length > 0 || services.length > 0 || 
      vulns.length > 0 || urls.length > 0 || sensitiveInfos.length > 0
    
    console.log('[Topology] Building graph, hasData:', hasData)

    const dataList: any[] = []
    
    // 1. Create Core Node (Task Center)
    const coreId = `task-${taskId}`
    const totalSubdomains = stats.subdomain || subdomains.length
    const totalPorts = stats.port || ports.length
    const totalVulns = stats.vuln || vulns.length
    const totalUrls = stats.url || urls.length
    
    dataList.push({
      id: coreId,
      target: taskName,
      type: 'core',
      status: 'active',
      tags: ['Task'],
      val: 20,
      color: '#22d3ee',
      description: `扫描任务核心。子域名: ${totalSubdomains}，端口: ${totalPorts}，漏洞: ${totalVulns}，URL: ${totalUrls}`
    })

    // 2. Create Cluster Nodes for each result type
    const clusters = [
      { id: 'cluster-subdomain', name: '子域名', count: totalSubdomains, color: '#a78bfa', items: subdomains },
      { id: 'cluster-port', name: '端口', count: totalPorts, color: '#60a5fa', items: ports },
      { id: 'cluster-service', name: 'Web服务', count: stats.service || services.length, color: '#34d399', items: services },
      { id: 'cluster-vuln', name: '漏洞', count: totalVulns, color: '#ef4444', items: vulns },
      { id: 'cluster-url', name: 'URL', count: totalUrls, color: '#f97316', items: urls },
      { id: 'cluster-sensitive', name: '敏感信息', count: stats.sensitive || sensitiveInfos.length, color: '#eab308', items: sensitiveInfos },
    ]

    clusters.forEach(cluster => {
      if (cluster.count > 0) {
        dataList.push({
          id: cluster.id,
          target: `${cluster.name} (${cluster.count})`,
          type: 'cluster',
          val: 12,
          color: cluster.color,
          parentId: coreId,
          description: `共发现 ${cluster.count} 个${cluster.name}`
        })

        // Add leaf nodes (limit to first 50 for performance)
        const items = cluster.items.slice(0, 50)
        items.forEach((item: any, index: number) => {
          const leafId = `${cluster.id}-${index}`
          let name = ''
          let desc = ''
          let leafColor = cluster.color

          switch (cluster.id) {
            case 'cluster-subdomain':
              name = item.data?.domain || item.domain || `子域名 ${index + 1}`
              desc = `IP: ${item.data?.ips?.join(', ') || item.ips?.join(', ') || '-'}`
              break
            case 'cluster-port':
              name = `${item.data?.ip || item.ip}:${item.data?.port || item.port}`
              desc = `服务: ${item.data?.service || item.service || '-'}`
              break
            case 'cluster-service':
              name = item.data?.url || item.url || `服务 ${index + 1}`
              desc = `标题: ${item.data?.title || item.title || '-'}`
              break
            case 'cluster-vuln':
              name = item.data?.name || item.name || `漏洞 ${index + 1}`
              desc = `等级: ${item.data?.severity || item.severity || '-'}`
              // Color by severity
              const severity = (item.data?.severity || item.severity || '').toLowerCase()
              if (severity === 'critical') leafColor = '#ef4444'
              else if (severity === 'high') leafColor = '#f97316'
              else if (severity === 'medium') leafColor = '#eab308'
              else if (severity === 'low') leafColor = '#3b82f6'
              break
            case 'cluster-url':
              name = item.data?.url || item.url || `URL ${index + 1}`
              desc = `方法: ${item.data?.method || item.method || 'GET'}`
              break
            case 'cluster-sensitive':
              name = item.data?.type || item.type || `敏感信息 ${index + 1}`
              desc = item.data?.match || item.match || '-'
              break
          }

          dataList.push({
            id: leafId,
            target: name,
            type: 'leaf',
            val: 4,
            color: leafColor,
            parentId: cluster.id,
            description: desc
          })
        })
      }
    })

    if (dataList.length === 0) {
      setIsLoadingGraph(false)
      return
    }

    // Clear existing graph
    nodesRef.current.forEach(n => {
      if (n.threeObject) sceneRef.current?.remove(n.threeObject)
    })
    linksRef.current.forEach(l => {
      if (l.threeObject) sceneRef.current?.remove(l.threeObject)
    })

    // Build nodes and links
    const nodes: GraphNode[] = []
    const links: GraphLink[] = []
    const nodeMap = new Map<string, GraphNode>()

    const addNode = (id: string, name: string, type: string, data?: any) => {
      if (!nodeMap.has(id)) {
        let color = data?.color || '#ffffff'
        let val = data?.val || 5

        const node: GraphNode = {
          id, name, type, val, color,
          data: data || { name, type },
          x: (Math.random() - 0.5) * 100,
          y: (Math.random() - 0.5) * 100,
          z: (Math.random() - 0.5) * 50
        }
        nodes.push(node)
        nodeMap.set(id, node)
      }
      return nodeMap.get(id)!
    }

    dataList.forEach((item: any) => {
      addNode(item.id, item.target, item.type, item)
      
      if (item.parentId) {
        links.push({
          source: item.parentId,
          target: item.id,
          color: 'rgba(255, 255, 255, 0.15)'
        })
      }
    })

    nodesRef.current = nodes
    linksRef.current = links

    // Create Glow Textures
    const createGlowTexture = () => {
      const canvas = document.createElement('canvas')
      canvas.width = 128
      canvas.height = 128
      const context = canvas.getContext('2d')
      if (context) {
        const gradient = context.createRadialGradient(64, 64, 0, 64, 64, 64)
        gradient.addColorStop(0, 'rgba(255,255,255,1)')
        gradient.addColorStop(0.2, 'rgba(255,255,255,0.8)')
        gradient.addColorStop(0.5, 'rgba(255,255,255,0.2)')
        gradient.addColorStop(1, 'rgba(0,0,0,0)')
        context.fillStyle = gradient
        context.fillRect(0, 0, 128, 128)
      }
      return new THREE.CanvasTexture(canvas)
    }

    const glowTexture = createGlowTexture()

    // Create 3D Objects for nodes
    nodes.forEach(node => {
      const group = new THREE.Group()
      
      const material = new THREE.SpriteMaterial({
        map: glowTexture,
        color: new THREE.Color(node.color),
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      })
      
      const sprite = new THREE.Sprite(material)
      sprite.scale.setScalar(node.val * 2)
      group.add(sprite)

      // Add label
      const canvas = document.createElement('canvas')
      const ctx = canvas.getContext('2d')
      if (ctx) {
        ctx.font = '20px Arial'
        const text = node.name.length > 20 ? node.name.slice(0, 20) + '...' : node.name
        const textWidth = ctx.measureText(text).width + 16
        canvas.width = textWidth
        canvas.height = 28
        ctx.font = '20px Arial'
        ctx.fillStyle = 'rgba(0, 0, 0, 0.6)'
        ctx.fillRect(0, 0, canvas.width, canvas.height)
        ctx.fillStyle = '#ffffff'
        ctx.fillText(text, 8, 20)
        
        const labelTexture = new THREE.CanvasTexture(canvas)
        const labelMaterial = new THREE.SpriteMaterial({ map: labelTexture, transparent: true })
        const labelSprite = new THREE.Sprite(labelMaterial)
        labelSprite.scale.set(textWidth / 5, 28 / 5, 1)
        labelSprite.position.y = node.val * 1.5 + 5
        group.add(labelSprite)
      }

      group.position.set(node.x || 0, node.y || 0, node.z || 0)
      node.threeObject = group
      sceneRef.current?.add(group)
    })

    // Create 3D Objects for links
    links.forEach(link => {
      const sourceNode = typeof link.source === 'string' ? nodeMap.get(link.source) : link.source as GraphNode
      const targetNode = typeof link.target === 'string' ? nodeMap.get(link.target) : link.target as GraphNode
      
      if (sourceNode && targetNode) {
        const geometry = new THREE.BufferGeometry().setFromPoints([
          new THREE.Vector3(sourceNode.x || 0, sourceNode.y || 0, sourceNode.z || 0),
          new THREE.Vector3(targetNode.x || 0, targetNode.y || 0, targetNode.z || 0)
        ])
        const material = new THREE.LineBasicMaterial({ 
          color: 0xffffff, 
          transparent: true, 
          opacity: 0.15 
        })
        const line = new THREE.Line(geometry, material)
        link.threeObject = line
        sceneRef.current?.add(line)
      }
    })

    // D3 Force Simulation
    const simulation = d3.forceSimulation<GraphNode>(nodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(links)
        .id(d => d.id)
        .distance(d => {
          const source = d.source as GraphNode
          const target = d.target as GraphNode
          if (source.type === 'core' || target.type === 'core') return 120
          if (source.type === 'cluster' || target.type === 'cluster') return 80
          return 40
        }))
      .force('charge', d3.forceManyBody().strength(-100))
      .force('center', d3.forceCenter(0, 0))
      .force('z', () => {
        nodes.forEach(n => {
          n.z = (n.z || 0) * 0.95
        })
      })
      .on('tick', () => {
        nodes.forEach(node => {
          if (node.threeObject) {
            node.threeObject.position.set(node.x || 0, node.y || 0, node.z || 0)
          }
        })
        links.forEach(link => {
          const sourceNode = link.source as GraphNode
          const targetNode = link.target as GraphNode
          if (link.threeObject && sourceNode && targetNode) {
            const positions = (link.threeObject as THREE.Line).geometry.attributes.position
            positions.setXYZ(0, sourceNode.x || 0, sourceNode.y || 0, sourceNode.z || 0)
            positions.setXYZ(1, targetNode.x || 0, targetNode.y || 0, targetNode.z || 0)
            positions.needsUpdate = true
          }
        })
      })
      .on('end', () => {
        setIsLoadingGraph(false)
      })
    
    simulationRef.current = simulation
    
    const timer = setTimeout(() => setIsLoadingGraph(false), 2000)
    return () => clearTimeout(timer)

  }, [taskId, taskName, subdomains, ports, services, vulns, urls, sensitiveInfos, stats, isDataLoading])

  // Camera Animation
  const flyToNode = (node: GraphNode) => {
    if (!cameraRef.current || !node.x) return

    const targetPos = { x: node.x || 0, y: node.y || 0, z: (node.z || 0) + 150 }

    anime({
      targets: cameraRef.current.position,
      x: targetPos.x,
      y: targetPos.y,
      z: targetPos.z,
      duration: 1000,
      easing: 'easeOutQuad'
    })
  }

  const resetCamera = () => {
    if (!cameraRef.current) return
    anime({
      targets: cameraRef.current.position,
      x: 0,
      y: 0,
      z: 400,
      duration: 1000,
      easing: 'easeOutQuad'
    })
    setSelectedNode(null)
  }

  return (
    <div className="relative w-full h-full min-h-[calc(100vh-220px)] bg-black overflow-hidden">
      {/* 3D Canvas Container */}
      <div ref={containerRef} className="absolute inset-0 cursor-grab active:cursor-grabbing" />

      {/* Loading Overlay */}
      {isLoadingGraph && (
        <div className="absolute inset-0 flex items-center justify-center bg-black/50 backdrop-blur-sm z-10">
          <div className="flex flex-col items-center gap-3">
            <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
            <span className="text-sm text-slate-300">正在构建资产星图...</span>
          </div>
        </div>
      )}

      {/* Title Overlay */}
      <div className="absolute top-4 left-4 z-20">
        <div className="bg-black/60 backdrop-blur-sm rounded-lg px-4 py-2 border border-slate-700/50">
          <span className="text-sm font-bold tracking-wider text-slate-100">任务资产星图</span>
        </div>
      </div>

      {/* Reset Button */}
      <div className="absolute top-4 right-4 z-20">
        <Button
          variant="outline"
          size="sm"
          onClick={resetCamera}
          className="bg-black/60 border-slate-700 text-slate-300 hover:bg-slate-800"
        >
          <RotateCcw className="h-4 w-4 mr-1" />
          重置视图
        </Button>
      </div>

      {/* Selected Node Detail Panel */}
      {selectedNode && (
        <div className="absolute bottom-4 left-4 right-4 z-20">
          <div className="bg-slate-900/95 backdrop-blur-md rounded-xl border border-slate-700/50 p-4 max-w-md">
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2">
                <div 
                  className="w-3 h-3 rounded-full" 
                  style={{ backgroundColor: selectedNode.color, boxShadow: `0 0 10px ${selectedNode.color}` }}
                />
                <span className="font-semibold text-white truncate max-w-[200px]">{selectedNode.name}</span>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 text-slate-400 hover:text-white"
                onClick={() => setSelectedNode(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
            
            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="text-xs">{selectedNode.type}</Badge>
              </div>
              {selectedNode.data?.description && (
                <p className="text-slate-400 text-xs">{selectedNode.data.description}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!isLoadingGraph && nodesRef.current.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center text-slate-400">
            <p className="text-lg mb-2">暂无扫描数据</p>
            <p className="text-sm">扫描完成后将自动构建资产星图</p>
          </div>
        </div>
      )}

      {/* Instructions */}
      <div className="absolute bottom-4 left-4 z-10 text-xs text-slate-500 space-y-1 font-mono pointer-events-none select-none bg-slate-900/60 backdrop-blur-sm p-3 rounded-lg border border-slate-800">
        <p className="flex items-center gap-2"><span className="text-cyan-400">●</span> [左键拖拽] 旋转视图</p>
        <p className="flex items-center gap-2"><span className="text-green-400">●</span> [右键拖拽] 平移视图</p>
        <p className="flex items-center gap-2"><span className="text-yellow-400">●</span> [滚轮] 缩放视图</p>
        <p className="flex items-center gap-2"><span className="text-purple-400">●</span> [点击节点] 查看详情</p>
      </div>
    </div>
  )
}
