import { useEffect, useState, useMemo, useRef } from 'react'
import Plot from 'react-plotly.js'
import styles from './BlochSphere.module.css'

const COLOR_ACCEPT = 'hsl(152, 48%, 60%)'
const COLOR_CRITICAL = 'hsl(6, 80%, 68%)'
const COLOR_WIRE = 'hsl(222, 18%, 26%)'
const COLOR_AXIS = 'hsl(222, 14%, 38%)'
const COLOR_TEXT = 'hsl(40, 10%, 72%)'

function generateSphereData() {
  const stepsU = 24
  const stepsV = 36
  const x = []
  const y = []
  const z = []

  for (let i = 0; i <= stepsU; i++) {
    const u = (Math.PI * i) / stepsU
    const rowX = []
    const rowY = []
    const rowZ = []
    for (let j = 0; j <= stepsV; j++) {
      const v = (2 * Math.PI * j) / stepsV
      rowX.push(Math.sin(u) * Math.cos(v))
      rowY.push(Math.sin(u) * Math.sin(v))
      rowZ.push(Math.cos(u))
    }
    x.push(rowX)
    y.push(rowY)
    z.push(rowZ)
  }
  return { x, y, z }
}

function generateCircle(plane) {
  const steps = 72
  const xs = []
  const ys = []
  const zs = []
  for (let i = 0; i <= steps; i++) {
    const angle = (2 * Math.PI * i) / steps
    if (plane === 'xy') {
      xs.push(Math.cos(angle))
      ys.push(Math.sin(angle))
      zs.push(0)
    } else if (plane === 'xz') {
      xs.push(Math.cos(angle))
      ys.push(0)
      zs.push(Math.sin(angle))
    } else if (plane === 'yz') {
      xs.push(0)
      ys.push(Math.cos(angle))
      zs.push(Math.sin(angle))
    }
  }
  return { xs, ys, zs }
}

export default function BlochSphere({
  coordinates = { x: 0, y: 0, z: 1 },
  collapsedCoordinates = null,
  isCollapsed = false,
  label = '|0⟩',
}) {
  const [animCoords, setAnimCoords] = useState(coordinates)
  const [animColor, setAnimColor] = useState(isCollapsed ? COLOR_CRITICAL : COLOR_ACCEPT)
  const animRef = useRef(null)

  const sphereSurface = useMemo(() => generateSphereData(), [])
  const circleXY = useMemo(() => generateCircle('xy'), [])
  const circleXZ = useMemo(() => generateCircle('xz'), [])
  const circleYZ = useMemo(() => generateCircle('yz'), [])

  useEffect(() => {
    if (animRef.current) {
      cancelAnimationFrame(animRef.current)
    }

    if (isCollapsed && collapsedCoordinates) {
      const startX = coordinates.x ?? 0
      const startY = coordinates.y ?? 0
      const startZ = coordinates.z ?? 0
      const targetX = collapsedCoordinates.x ?? 0
      const targetY = collapsedCoordinates.y ?? 0
      const targetZ = collapsedCoordinates.z ?? 0

      const startTime = performance.now()
      const duration = 600

      const animate = (now) => {
        const elapsed = now - startTime
        const progress = Math.min(elapsed / duration, 1.0)
        const ease = 1 - Math.pow(1 - progress, 3)

        const curX = startX + (targetX - startX) * ease
        const curY = startY + (targetY - startY) * ease
        const curZ = startZ + (targetZ - startZ) * ease

        setAnimCoords({ x: curX, y: curY, z: curZ })
        setAnimColor(progress > 0.5 ? COLOR_CRITICAL : COLOR_ACCEPT)

        if (progress < 1.0) {
          animRef.current = requestAnimationFrame(animate)
        } else {
          setAnimCoords({ x: targetX, y: targetY, z: targetZ })
          setAnimColor(COLOR_CRITICAL)
        }
      }

      animRef.current = requestAnimationFrame(animate)
    } else {
      setAnimCoords(coordinates)
      setAnimColor(COLOR_ACCEPT)
    }

    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current)
    }
  }, [coordinates, collapsedCoordinates, isCollapsed])

  const curX = animCoords?.x ?? 0
  const curY = animCoords?.y ?? 0
  const curZ = animCoords?.z ?? 0

  const plotData = useMemo(() => {
    return [
      // 1. Semi-transparent sphere surface
      {
        type: 'surface',
        x: sphereSurface.x,
        y: sphereSurface.y,
        z: sphereSurface.z,
        showscale: false,
        opacity: 0.07,
        colorscale: [
          [0, 'hsl(222, 16%, 30%)'],
          [1, 'hsl(222, 16%, 30%)'],
        ],
        hoverinfo: 'none',
      },
      // 2. Equator Ring (XY)
      {
        type: 'scatter3d',
        mode: 'lines',
        x: circleXY.xs,
        y: circleXY.ys,
        z: circleXY.zs,
        line: { color: COLOR_WIRE, width: 1.5 },
        hoverinfo: 'none',
      },
      // 3. Meridian Ring (XZ)
      {
        type: 'scatter3d',
        mode: 'lines',
        x: circleXZ.xs,
        y: circleXZ.ys,
        z: circleXZ.zs,
        line: { color: COLOR_WIRE, width: 1.5 },
        hoverinfo: 'none',
      },
      // 4. Meridian Ring (YZ)
      {
        type: 'scatter3d',
        mode: 'lines',
        x: circleYZ.xs,
        y: circleYZ.ys,
        z: circleYZ.zs,
        line: { color: COLOR_WIRE, width: 1.5 },
        hoverinfo: 'none',
      },
      // 5. Axes Lines
      {
        type: 'scatter3d',
        mode: 'lines',
        x: [-1.25, 1.25, null, 0, 0, null, 0, 0],
        y: [0, 0, null, -1.25, 1.25, null, 0, 0],
        z: [0, 0, null, 0, 0, null, -1.25, 1.25],
        line: { color: COLOR_AXIS, width: 1.5 },
        hoverinfo: 'none',
      },
      // 6. Axis Labels & Standard Basis Reference Labels
      {
        type: 'scatter3d',
        mode: 'text',
        x: [0, 0, 1.28, -1.28, 0, 0],
        y: [0, 0, 0, 0, 1.28, -1.28],
        z: [1.25, -1.25, 0, 0, 0, 0],
        text: ['|0⟩ (+z)', '|1⟩ (-z)', '|+⟩ (+x)', '|-⟩ (-x)', '|+i⟩ (+y)', '|-i⟩ (-y)'],
        textfont: {
          family: 'Azeret Mono, monospace',
          size: 10,
          color: COLOR_TEXT,
        },
        hoverinfo: 'none',
      },
      // 7. Ghost Pre-collapse Marker if collapsed
      ...(isCollapsed && collapsedCoordinates
        ? [
            {
              type: 'scatter3d',
              mode: 'markers+lines',
              x: [coordinates.x, collapsedCoordinates.x],
              y: [coordinates.y, collapsedCoordinates.y],
              z: [coordinates.z, collapsedCoordinates.z],
              marker: {
                size: 3,
                color: 'hsl(40, 8%, 56%)',
              },
              line: {
                color: 'hsl(40, 10%, 66%)',
                width: 2,
                dash: 'dot',
              },
              hoverinfo: 'text',
              text: ['Pre-measurement State', 'Collapsed State'],
            },
          ]
        : []),
      // 8. State Vector Line
      {
        type: 'scatter3d',
        mode: 'lines',
        x: [0, curX],
        y: [0, curY],
        z: [0, curZ],
        line: {
          color: animColor,
          width: 5,
        },
        hoverinfo: 'none',
      },
      // 9. State Vector Tip Marker
      {
        type: 'scatter3d',
        mode: 'markers+text',
        x: [curX],
        y: [curY],
        z: [curZ],
        marker: {
          size: 6,
          color: animColor,
          symbol: 'circle',
        },
        text: [label || 'Ψ'],
        textposition: 'top center',
        textfont: {
          family: 'Azeret Mono, monospace',
          size: 11,
          color: animColor,
        },
        hoverinfo: 'text',
        hovertext: `x: ${curX.toFixed(3)}, y: ${curY.toFixed(3)}, z: ${curZ.toFixed(3)}`,
      },
    ]
  }, [
    sphereSurface,
    circleXY,
    circleXZ,
    circleYZ,
    curX,
    curY,
    curZ,
    animColor,
    label,
    isCollapsed,
    coordinates,
    collapsedCoordinates,
  ])

  const layout = useMemo(() => {
    return {
      autosize: true,
      margin: { l: 0, r: 0, b: 0, t: 0, pad: 0 },
      paper_bgcolor: 'rgba(0,0,0,0)',
      plot_bgcolor: 'rgba(0,0,0,0)',
      showlegend: false,
      scene: {
        aspectmode: 'cube',
        camera: {
          eye: { x: 1.45, y: 1.45, z: 1.15 },
        },
        xaxis: {
          range: [-1.4, 1.4],
          showgrid: true,
          gridcolor: 'hsl(222, 16%, 22%)',
          gridwidth: 1,
          zeroline: true,
          zerolinecolor: 'hsl(222, 18%, 28%)',
          showticklabels: false,
          showspikes: false,
          title: { text: '' },
        },
        yaxis: {
          range: [-1.4, 1.4],
          showgrid: true,
          gridcolor: 'hsl(222, 16%, 22%)',
          gridwidth: 1,
          zeroline: true,
          zerolinecolor: 'hsl(222, 18%, 28%)',
          showticklabels: false,
          showspikes: false,
          title: { text: '' },
        },
        zaxis: {
          range: [-1.4, 1.4],
          showgrid: true,
          gridcolor: 'hsl(222, 16%, 22%)',
          gridwidth: 1,
          zeroline: true,
          zerolinecolor: 'hsl(222, 18%, 28%)',
          showticklabels: false,
          showspikes: false,
          title: { text: '' },
        },
      },
    }
  }, [])

  const config = useMemo(() => {
    return {
      displayModeBar: false,
      responsive: true,
      scrollZoom: true,
    }
  }, [])

  return (
    <div className={styles.blochContainer}>
      <Plot
        data={plotData}
        layout={layout}
        config={config}
        useResizeHandler
        className={styles.plot}
      />
    </div>
  )
}
