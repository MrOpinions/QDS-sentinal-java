import { useEffect, useRef } from 'react'

/**
 * Ambient background for the landing page. One canvas, one rAF loop.
 *
 * Two layers, both deliberately faint:
 *   - the channel lattice: a dot grid that bends toward the cursor like a
 *     gravity well. This is the page's thesis made literal - observing the
 *     quantum channel disturbs it.
 *   - the atom: three inclined orbits and a nucleus, rotating slowly.
 *
 * Honours prefers-reduced-motion (renders one static frame) and pauses
 * entirely while the tab is hidden.
 */

const GRID_SPACING = 34
const WARP_RADIUS = 230
const WARP_STRENGTH = 32
const ORBIT_TILTS = [0, (2 * Math.PI) / 3, (4 * Math.PI) / 3]

export default function QuantumField() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    // Target follows the real cursor; eased trails behind it so the well has weight.
    const target = { x: -9999, y: -9999 }
    const eased = { x: -9999, y: -9999 }

    let width = 0
    let height = 0
    let frame = 0
    let spin = 0

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      width = canvas.clientWidth
      height = canvas.clientHeight
      canvas.width = Math.floor(width * dpr)
      canvas.height = Math.floor(height * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    function drawLattice() {
      ctx.fillStyle = 'hsl(190, 70%, 62%)'
      for (let x = GRID_SPACING / 2; x < width; x += GRID_SPACING) {
        for (let y = GRID_SPACING / 2; y < height; y += GRID_SPACING) {
          const dx = eased.x - x
          const dy = eased.y - y
          const dist = Math.hypot(dx, dy)

          let px = x
          let py = y
          let radius = 1
          let alpha = 0.16

          if (dist < WARP_RADIUS && dist > 0.01) {
            // Inverse falloff: points near the cursor fall further into the well.
            const pull = (1 - dist / WARP_RADIUS) ** 2
            px += (dx / dist) * pull * WARP_STRENGTH
            py += (dy / dist) * pull * WARP_STRENGTH
            radius = 1 + pull * 2.2
            alpha = 0.16 + pull * 0.62
          }

          ctx.globalAlpha = alpha
          ctx.beginPath()
          ctx.arc(px, py, radius, 0, Math.PI * 2)
          ctx.fill()
        }
      }
      ctx.globalAlpha = 1
    }

    function drawAtom() {
      const cx = width / 2
      const cy = height * 0.46
      // Tied mostly to width and capped, so it stays ambient on a tall phone
      // instead of filling the screen.
      const scale = Math.min(width * 0.38, height * 0.3, 430)

      ctx.save()
      ctx.translate(cx, cy)
      ctx.strokeStyle = 'hsl(190, 60%, 70%)'
      ctx.lineWidth = 1

      ORBIT_TILTS.forEach((tilt, i) => {
        const angle = tilt + spin * (i % 2 === 0 ? 1 : -1)

        ctx.globalAlpha = 0.035
        ctx.beginPath()
        ctx.ellipse(0, 0, scale, scale * 0.33, angle, 0, Math.PI * 2)
        ctx.stroke()

        // Electron riding this orbit, in the orbit's own rotated frame.
        const phase = spin * 2.1 + (i * Math.PI * 2) / 3
        const ox = Math.cos(phase) * scale
        const oy = Math.sin(phase) * scale * 0.33
        ctx.globalAlpha = 0.085
        ctx.beginPath()
        ctx.arc(
          ox * Math.cos(angle) - oy * Math.sin(angle),
          ox * Math.sin(angle) + oy * Math.cos(angle),
          2.4,
          0,
          Math.PI * 2,
        )
        ctx.fillStyle = 'hsl(190, 70%, 72%)'
        ctx.fill()
      })

      ctx.globalAlpha = 0.08
      ctx.beginPath()
      ctx.arc(0, 0, 5, 0, Math.PI * 2)
      ctx.fillStyle = 'hsl(40, 30%, 88%)'
      ctx.fill()

      ctx.globalAlpha = 1
      ctx.restore()
    }

    function render() {
      ctx.clearRect(0, 0, width, height)
      drawAtom()
      drawLattice()
    }

    function tick() {
      eased.x += (target.x - eased.x) * 0.12
      eased.y += (target.y - eased.y) * 0.12
      spin += 0.0022
      render()
      frame = requestAnimationFrame(tick)
    }

    function start() {
      if (frame || reduceMotion) return
      frame = requestAnimationFrame(tick)
    }

    function stop() {
      cancelAnimationFrame(frame)
      frame = 0
    }

    function onPointerMove(e) {
      target.x = e.clientX
      target.y = e.clientY
      if (reduceMotion) return
      // Snap on the first move so the well doesn't fly in from off-screen.
      if (eased.x < -1000) {
        eased.x = target.x
        eased.y = target.y
      }
    }

    function onPointerLeave() {
      target.x = -9999
      target.y = -9999
    }

    function onVisibility() {
      if (document.hidden) stop()
      else start()
    }

    resize()
    if (reduceMotion) render()
    else start()

    window.addEventListener('resize', resize)
    window.addEventListener('pointermove', onPointerMove, { passive: true })
    document.addEventListener('pointerleave', onPointerLeave)
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      stop()
      window.removeEventListener('resize', resize)
      window.removeEventListener('pointermove', onPointerMove)
      document.removeEventListener('pointerleave', onPointerLeave)
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [])

  return <canvas ref={canvasRef} className="quantumField" aria-hidden="true" />
}
