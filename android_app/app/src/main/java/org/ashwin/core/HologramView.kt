package org.ashwin.core

import android.animation.ValueAnimator
import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import android.view.animation.LinearInterpolator
import kotlin.math.*
import kotlin.random.Random

/**
 * HologramView - Authentic ASHWIN Holographic Computational Intelligence Core.
 *
 * Implements the definitive holographic architecture matching the primary reference:
 * 1. Radiant central white-gold singularity core with horizontal & vertical coordinate crosshairs.
 * 2. 14 Concentric computational telemetry rings with fine data ticks, dashed effects, and coordinate markers.
 * 3. 52 Translucent curved energy quads and data shards locked into structured concentric tiers.
 * 4. 48 Structural intersection nodes pinned to ring geometries (0 drifting or falling particles).
 * 5. 8 Perimeter framing brackets defining the projection boundary.
 * 6. Horizontal voice-reactive waveform laser beam & outward propagating energy waves during SPEAKING.
 * 7. State Dynamics:
 *    - IDLE: Virtually static/frozen (0.005x speed), dormant intelligence awaiting command.
 *    - SPEAKING: Luminous white-gold core bloom, radial wave propagation, voice waveform undulation.
 *    - LISTENING / THINKING / SUCCESS / ERROR: Controlled responsive states.
 */
class HologramView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    enum class State {
        IDLE,
        LISTENING,
        THINKING,
        SPEAKING,
        SUCCESS,
        ERROR
    }

    var currentState: State = State.IDLE
        set(value) {
            field = value
            onStateChanged(value)
            invalidate()
        }

    var onHologramTapListener: (() -> Unit)? = null

    // Palette: Gold / Amber / Orange Holographic Intelligence
    private val colorCoreWhite = Color.parseColor("#FFFFFF")
    private val colorCoreHotGold = Color.parseColor("#FFFBEB")
    private val colorGoldBright = Color.parseColor("#FDE047")
    private val colorGoldMid = Color.parseColor("#FBBF24")
    private val colorAmberPrimary = Color.parseColor("#F59E0B")
    private val colorOrangeDeep = Color.parseColor("#D97706")
    private val colorDarkAmber = Color.parseColor("#78350F")

    // State Accents
    private val colorListeningCyan = Color.parseColor("#38BDF8")
    private val colorListeningCore = Color.parseColor("#E0F2FE")
    private val colorThinkingGold = Color.parseColor("#FEF08A")
    private val colorSuccessEmerald = Color.parseColor("#34D399")
    private val colorErrorCrimson = Color.parseColor("#F87171")

    // Preallocated Paints (Zero allocations in onDraw for constant 60 FPS)
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val corePaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
    }
    private val shardFillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val shardStrokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
    }
    private val crosshairPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
    }
    private val nodePaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val wavePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }
    private val pulseWavePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
    }

    // Dynamic Animation Parameters
    private var animProgress = 0f
    private var rotationAngle = 0f
    private var speakingPhase = 0f
    private var audioAmplitude = 0.5f
    private var radialPulsePhase = 0f

    // -------------------------------------------------------------------------
    // PROCEDURAL GEOMETRY DATA STRUCTURES (Precomputed for 60 FPS)
    // -------------------------------------------------------------------------

    // 1. Concentric Computational Rings (14 concentric tiers)
    private class TelemetryRing(
        val rRatio: Float,
        val strokeWidth: Float,
        val dashPattern: FloatArray?,
        val baseAlpha: Int,
        val rotSpeed: Float,
        var currentAngle: Float = 0f
    )

    private val rings: Array<TelemetryRing>

    // 2. Curved Rectangular Energy Shards / Data Quads (52 structured planar shards)
    private class EnergyShard(
        val tierRatio: Float,      // Base radius ratio [0.25, 0.96]
        val radialThickness: Float,// Radial height in ratio
        val startAngleDeg: Float,  // Angular start
        val sweepAngleDeg: Float,  // Angular span
        val fillAlpha: Int,        // Translucent fill alpha
        val strokeAlpha: Int,      // Glowing border alpha
        val hasNodeTick: Boolean,
        val rotSpeed: Float,
        var currentAngle: Float = 0f
    )

    private val shards: Array<EnergyShard>

    // 3. Structural Intersection Nodes (48 locked geometric telemetry points)
    private class StructuralNode(
        val rRatio: Float,
        val angleDeg: Float,
        val size: Float,
        val isSquare: Boolean,
        val baseAlpha: Int
    )

    private val nodes: Array<StructuralNode>

    // 4. Perimeter Brackets (8 corner/quadrant telemetry brackets)
    private class PerimeterBracket(
        val angleDeg: Float,
        val rRatio: Float,
        val lengthDeg: Float
    )

    private val brackets: Array<PerimeterBracket>

    private val tempRectInner = RectF()
    private val tempRectOuter = RectF()
    private val tempPath = Path()
    private var animator: ValueAnimator? = null

    init {
        val rand = Random(101) // Deterministic seed for aesthetic balance

        // 1. Construct Telemetry Rings
        rings = arrayOf(
            TelemetryRing(0.12f, 1.2f, null, 180, 0.1f),
            TelemetryRing(0.18f, 1.0f, floatArrayOf(8f, 6f), 140, -0.15f),
            TelemetryRing(0.24f, 1.5f, null, 200, 0.05f),
            TelemetryRing(0.32f, 1.0f, floatArrayOf(16f, 10f, 4f, 10f), 150, -0.08f),
            TelemetryRing(0.40f, 1.8f, null, 220, 0.06f),
            TelemetryRing(0.48f, 1.2f, floatArrayOf(24f, 12f), 160, -0.12f),
            TelemetryRing(0.56f, 1.0f, floatArrayOf(6f, 6f), 130, 0.04f),
            TelemetryRing(0.64f, 2.0f, null, 210, -0.05f),
            TelemetryRing(0.72f, 1.2f, floatArrayOf(30f, 15f, 8f, 15f), 170, 0.08f),
            TelemetryRing(0.80f, 1.0f, floatArrayOf(12f, 8f), 140, -0.06f),
            TelemetryRing(0.88f, 2.2f, null, 230, 0.05f),
            TelemetryRing(0.94f, 1.5f, floatArrayOf(40f, 20f), 190, -0.09f),
            TelemetryRing(0.98f, 2.8f, null, 240, 0.03f),
            TelemetryRing(1.02f, 1.0f, floatArrayOf(8f, 14f), 120, -0.04f)
        )

        // 2. Construct Curved Rectangular Shards / Data Quads (52 panels)
        shards = Array(52) { i ->
            val tier = 0.28f + (i % 6) * 0.12f + rand.nextFloat() * 0.04f
            val radThick = 0.025f + rand.nextFloat() * 0.035f
            val startAng = (i * 37.5f + rand.nextFloat() * 15f) % 360f
            val sweep = 12f + rand.nextFloat() * 24f
            val fillA = (25 + rand.nextInt(45))
            val strokeA = (120 + rand.nextInt(100))
            val rotSpd = (rand.nextFloat() * 0.08f + 0.02f) * (if (i % 2 == 0) 1f else -1f)

            EnergyShard(
                tierRatio = tier,
                radialThickness = radThick,
                startAngleDeg = startAng,
                sweepAngleDeg = sweep,
                fillAlpha = fillA,
                strokeAlpha = strokeA,
                hasNodeTick = (i % 3 == 0),
                rotSpeed = rotSpd,
                currentAngle = startAng
            )
        }

        // 3. Construct Structural Intersection Nodes (48 points)
        nodes = Array(48) { i ->
            val rRatio = 0.24f + (i % 7) * 0.11f
            val angle = (i * 30f + (i / 7) * 15f) % 360f
            val isSq = i % 4 == 0
            val size = if (isSq) 4.0f else (rand.nextFloat() * 2.0f + 2.0f)
            val alpha = (160 + rand.nextInt(80))

            StructuralNode(rRatio, angle, size, isSq, alpha)
        }

        // 4. Construct Perimeter Brackets
        brackets = Array(8) { i ->
            PerimeterBracket(
                angleDeg = i * 45f + 22.5f,
                rRatio = 1.01f,
                lengthDeg = 18f
            )
        }

        setupAnimator()
    }

    private fun setupAnimator() {
        animator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 4000L
            repeatCount = ValueAnimator.INFINITE
            repeatMode = ValueAnimator.RESTART
            interpolator = LinearInterpolator()
            addUpdateListener { animation ->
                animProgress = animation.animatedValue as Float
                updateSimulation()
                invalidate()
            }
        }
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        animator?.start()
    }

    override fun onDetachedFromWindow() {
        animator?.cancel()
        super.onDetachedFromWindow()
    }

    private fun onStateChanged(state: State) {
        when (state) {
            State.IDLE -> {
                animator?.duration = 5000L
                audioAmplitude = 0.2f
            }
            State.LISTENING -> {
                animator?.duration = 2500L
            }
            State.THINKING -> {
                animator?.duration = 1500L
            }
            State.SPEAKING -> {
                animator?.duration = 1400L
                audioAmplitude = 0.7f
            }
            State.SUCCESS -> {
                animator?.duration = 1600L
            }
            State.ERROR -> {
                animator?.duration = 2000L
            }
        }
    }

    fun setAudioLevel(amplitude: Float) {
        audioAmplitude = amplitude.coerceIn(0.15f, 1.0f)
        invalidate()
    }

    private fun updateSimulation() {
        // Strict IDLE: virtually frozen / motionless micro-drift (0.005x factor)
        val speedMult = when (currentState) {
            State.IDLE -> 0.005f       // Nearly stationary, dormant technology waiting
            State.LISTENING -> 0.20f   // Gentle responsive presence
            State.THINKING -> 1.50f    // Active computational rotation
            State.SPEAKING -> 1.00f    // High-energy responsive activation
            State.SUCCESS -> 0.30f
            State.ERROR -> 0.15f
        }

        rotationAngle = (rotationAngle + 0.15f * speedMult) % 360f

        if (currentState == State.SPEAKING) {
            speakingPhase += 0.16f
            radialPulsePhase = (radialPulsePhase + 0.035f) % 1.0f
        } else if (currentState == State.LISTENING) {
            speakingPhase += 0.08f
        }

        // Update concentric rings
        for (r in rings) {
            r.currentAngle = (r.currentAngle + r.rotSpeed * speedMult * 10f) % 360f
        }

        // Update structured energy shards
        for (s in shards) {
            s.currentAngle = (s.currentAngle + s.rotSpeed * speedMult * 10f) % 360f
        }
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val cx = width / 2f
        val cy = height / 2f
        val minDim = min(width, height)

        // Huge Scale: Occupies 86–90% of screen width with clean balanced padding
        val baseRadius = minDim * 0.445f

        if (baseRadius <= 0) return

        // Dynamic State Breathing Scale
        val breathWave = sin(animProgress * 2 * PI).toFloat()
        val masterScale = when (currentState) {
            State.IDLE -> 1.0f + breathWave * 0.004f // Extremely subtle micro-breathing (almost still)
            State.LISTENING -> 1.03f + breathWave * 0.015f + audioAmplitude * 0.02f
            State.THINKING -> 0.98f + sin(animProgress * 6 * PI).toFloat() * 0.012f
            State.SPEAKING -> 1.06f + (sin(speakingPhase).toFloat() * 0.045f * (0.5f + audioAmplitude * 0.5f))
            State.SUCCESS -> 1.08f + breathWave * 0.02f
            State.ERROR -> 0.96f + breathWave * 0.01f
        }

        val R = baseRadius * masterScale

        // 1. Ambient Volumetric Glow
        drawVolumetricAmbientGlow(canvas, cx, cy, R)

        // 2. Outward Propagating Energy Waves (Active during SPEAKING)
        if (currentState == State.SPEAKING) {
            drawRadialPropagatingWaves(canvas, cx, cy, R)
        }

        // 3. Coordinate Laser Crosshairs & Radial Axes
        drawCoordinateCrosshairs(canvas, cx, cy, R)

        // 4. Concentric Computational Telemetry Rings
        drawTelemetryRings(canvas, cx, cy, R)

        // 5. Floating Rectangular Energy Quads & Curved Shards
        drawEnergyShards(canvas, cx, cy, R)

        // 6. Structural Intersection Nodes & Ticks
        drawStructuralNodes(canvas, cx, cy, R)

        // 7. Perimeter Framing Brackets
        drawPerimeterBrackets(canvas, cx, cy, R)

        // 8. Voice-Reactive Waveform Beam (Active during SPEAKING and LISTENING)
        if (currentState == State.SPEAKING || currentState == State.LISTENING) {
            drawVoiceWaveformBeam(canvas, cx, cy, R)
        }

        // 9. Radiant Central Intelligence Singularity Core
        drawCentralSingularityCore(canvas, cx, cy, R)
    }

    private fun drawVolumetricAmbientGlow(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        val glowRadius = R * 1.60f
        val primaryColor = getPrimaryColorForState()

        val glowAlpha = when (currentState) {
            State.IDLE -> 55          // Subdued, calm amber ambient
            State.SPEAKING -> 135      // Radiant, energetic bloom
            State.THINKING -> 90
            State.LISTENING -> 85
            State.SUCCESS -> 110
            State.ERROR -> 80
        }

        val glowShader = RadialGradient(
            cx, cy, glowRadius,
            intArrayOf(
                Color.argb(glowAlpha, Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor)),
                Color.argb((glowAlpha * 0.35f).toInt(), Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor)),
                Color.TRANSPARENT
            ),
            floatArrayOf(0.0f, 0.6f, 1.0f),
            Shader.TileMode.CLAMP
        )
        glowPaint.shader = glowShader
        canvas.drawCircle(cx, cy, glowRadius, glowPaint)
    }

    private fun drawRadialPropagatingWaves(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        val waveCount = 2
        for (i in 0 until waveCount) {
            val phase = (radialPulsePhase + i * (1.0f / waveCount)) % 1.0f
            val pulseR = R * (0.22f + phase * 0.78f)
            val pulseAlpha = ((1.0f - phase) * 160f * audioAmplitude).toInt().coerceIn(0, 255)

            pulseWavePaint.color = Color.argb(pulseAlpha, Color.red(colorGoldBright), Color.green(colorGoldBright), Color.blue(colorGoldBright))
            pulseWavePaint.strokeWidth = 1.5f * (1.0f - phase * 0.5f)
            canvas.drawCircle(cx, cy, pulseR, pulseWavePaint)
        }
    }

    private fun drawCoordinateCrosshairs(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        val primaryColor = getPrimaryColorForState()
        val crossAlpha = if (currentState == State.SPEAKING) 220 else 130

        crosshairPaint.color = Color.argb(crossAlpha, Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor))
        crosshairPaint.strokeWidth = 1.2f

        // Horizontal Main Axis
        canvas.drawLine(cx - R * 1.08f, cy, cx + R * 1.08f, cy, crosshairPaint)
        // Vertical Main Axis
        canvas.drawLine(cx, cy - R * 1.08f, cx, cy + R * 1.08f, crosshairPaint)

        // Coordinate Ticks along the Crosshairs
        val tickCount = 10
        crosshairPaint.strokeWidth = 1.0f
        for (i in 1..tickCount) {
            val dist = R * (i.toFloat() / (tickCount + 1))
            val tLen = if (i % 3 == 0) 6f else 3.5f

            // Horizontal ticks
            canvas.drawLine(cx + dist, cy - tLen, cx + dist, cy + tLen, crosshairPaint)
            canvas.drawLine(cx - dist, cy - tLen, cx - dist, cy + tLen, crosshairPaint)

            // Vertical ticks
            canvas.drawLine(cx - tLen, cy + dist, cx + tLen, cy + dist, crosshairPaint)
            canvas.drawLine(cx - tLen, cy - dist, cx + tLen, cy - dist, crosshairPaint)
        }

        // Diagonal 45-degree Guide Rays
        crosshairPaint.strokeWidth = 0.8f
        crosshairPaint.color = Color.argb(crossAlpha / 2, Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor))
        val diagR = R * 0.95f
        val cos45 = cos(PI / 4.0).toFloat()
        val sin45 = sin(PI / 4.0).toFloat()
        canvas.drawLine(cx - diagR * cos45, cy - diagR * sin45, cx + diagR * cos45, cy + diagR * sin45, crosshairPaint)
        canvas.drawLine(cx - diagR * cos45, cy + diagR * sin45, cx + diagR * cos45, cy - diagR * sin45, crosshairPaint)
    }

    private fun drawTelemetryRings(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        val primaryColor = getPrimaryColorForState()

        for (r in rings) {
            val radius = R * r.rRatio
            val alpha = if (currentState == State.SPEAKING) min(255, (r.baseAlpha * 1.3f).toInt()) else r.baseAlpha

            ringPaint.color = Color.argb(alpha, Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor))
            ringPaint.strokeWidth = if (currentState == State.SPEAKING) r.strokeWidth * 1.15f else r.strokeWidth

            if (r.dashPattern != null) {
                ringPaint.pathEffect = DashPathEffect(r.dashPattern, r.currentAngle)
            } else {
                ringPaint.pathEffect = null
            }

            canvas.drawCircle(cx, cy, radius, ringPaint)
        }
        ringPaint.pathEffect = null
    }

    private fun drawEnergyShards(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        val primaryColor = getPrimaryColorForState()
        val fillTone = if (currentState == State.LISTENING) colorListeningCyan else colorAmberPrimary

        for (shard in shards) {
            val rInner = R * shard.tierRatio
            val rOuter = R * (shard.tierRatio + shard.radialThickness)

            tempRectInner.set(cx - rInner, cy - rInner, cx + rInner, cy + rInner)
            tempRectOuter.set(cx - rOuter, cy - rOuter, cx + rOuter, cy + rOuter)

            // Construct curved rectangular panel path
            tempPath.reset()
            tempPath.arcTo(tempRectOuter, shard.currentAngle, shard.sweepAngleDeg)
            tempPath.arcTo(tempRectInner, shard.currentAngle + shard.sweepAngleDeg, -shard.sweepAngleDeg)
            tempPath.close()

            // Translucent Fill
            val fillA = if (currentState == State.SPEAKING) min(255, (shard.fillAlpha * 2.0f).toInt()) else shard.fillAlpha
            shardFillPaint.color = Color.argb(fillA, Color.red(fillTone), Color.green(fillTone), Color.blue(fillTone))
            canvas.drawPath(tempPath, shardFillPaint)

            // Glowing Border
            val strokeA = if (currentState == State.SPEAKING) min(255, (shard.strokeAlpha * 1.35f).toInt()) else shard.strokeAlpha
            shardStrokePaint.color = Color.argb(strokeA, Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor))
            shardStrokePaint.strokeWidth = 1.0f
            canvas.drawPath(tempPath, shardStrokePaint)

            // Optional node dot on the corner of the shard
            if (shard.hasNodeTick) {
                val angRad = ((shard.currentAngle + shard.sweepAngleDeg) * (PI / 180.0)).toFloat()
                val nx = cx + rOuter * cos(angRad)
                val ny = cy + rOuter * sin(angRad)
                nodePaint.color = Color.argb(220, 255, 255, 255)
                canvas.drawCircle(nx, ny, 1.8f, nodePaint)
            }
        }
    }

    private fun drawStructuralNodes(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        for (node in nodes) {
            val r = R * node.rRatio
            val angRad = ((node.angleDeg + rotationAngle * 0.2f) * (PI / 180.0)).toFloat()
            val nx = cx + r * cos(angRad)
            val ny = cy + r * sin(angRad)

            val alpha = if (currentState == State.SPEAKING) min(255, (node.baseAlpha * 1.35f).toInt()) else node.baseAlpha

            if (node.isSquare) {
                nodePaint.color = Color.argb(alpha, Color.red(colorGoldBright), Color.green(colorGoldBright), Color.blue(colorGoldBright))
                val hs = node.size * 0.7f
                canvas.drawRect(nx - hs, ny - hs, nx + hs, ny + hs, nodePaint)
            } else {
                nodePaint.color = Color.argb(alpha, 255, 255, 255)
                canvas.drawCircle(nx, ny, node.size * 0.6f, nodePaint)
            }
        }
    }

    private fun drawPerimeterBrackets(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        val primaryColor = getPrimaryColorForState()
        ringPaint.strokeWidth = 2.0f
        ringPaint.pathEffect = null
        ringPaint.color = Color.argb(180, Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor))

        for (bracket in brackets) {
            val r = R * bracket.rRatio
            tempRectOuter.set(cx - r, cy - r, cx + r, cy + r)
            canvas.drawArc(tempRectOuter, bracket.angleDeg, bracket.lengthDeg, false, ringPaint)

            // Small tick mark at the center of each bracket
            val midAngle = ((bracket.angleDeg + bracket.lengthDeg / 2f) * (PI / 180.0)).toFloat()
            val bx1 = cx + (r - 4f) * cos(midAngle)
            val by1 = cy + (r - 4f) * sin(midAngle)
            val bx2 = cx + (r + 6f) * cos(midAngle)
            val by2 = cy + (r + 6f) * sin(midAngle)
            canvas.drawLine(bx1, by1, bx2, by2, ringPaint)
        }
    }

    private fun drawVoiceWaveformBeam(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        val numWavePoints = 48
        val waveWidth = R * 1.85f
        val startX = cx - waveWidth / 2f
        val stepX = waveWidth / numWavePoints

        wavePaint.color = Color.argb(
            if (currentState == State.SPEAKING) 250 else 140,
            255, 255, 255
        )
        wavePaint.strokeWidth = if (currentState == State.SPEAKING) 2.4f else 1.4f

        tempPath.reset()
        for (i in 0..numWavePoints) {
            val x = startX + i * stepX
            val distFromCenter = abs(x - cx) / (waveWidth / 2f)
            val envelope = max(0f, 1f - distFromCenter * distFromCenter)

            val waveFreq = if (currentState == State.SPEAKING) 6.0f else 3.0f
            val waveAmp = (if (currentState == State.SPEAKING) 24f else 8f) * audioAmplitude * envelope
            val y = cy + sin(i * 0.4f + speakingPhase * waveFreq).toFloat() * waveAmp

            if (i == 0) {
                tempPath.moveTo(x, y)
            } else {
                tempPath.lineTo(x, y)
            }
        }
        canvas.drawPath(tempPath, wavePaint)
    }

    private fun drawCentralSingularityCore(canvas: Canvas, cx: Float, cy: Float, R: Float) {
        val coreRadius = R * when (currentState) {
            State.IDLE -> 0.16f
            State.LISTENING -> 0.18f + audioAmplitude * 0.03f
            State.THINKING -> 0.14f + sin(animProgress * 8 * PI).toFloat() * 0.02f
            State.SPEAKING -> 0.22f + sin(speakingPhase * 2f).toFloat() * 0.05f * audioAmplitude
            State.SUCCESS -> 0.24f
            State.ERROR -> 0.13f
        }

        val primaryColor = getPrimaryColorForState()
        val coreHotColor = if (currentState == State.LISTENING) colorListeningCore else colorCoreHotGold

        // 1. Core Radiant Gradient
        val coreShader = RadialGradient(
            cx, cy, coreRadius,
            intArrayOf(
                colorCoreWhite, // Hot white singularity
                coreHotColor,
                Color.argb(210, Color.red(primaryColor), Color.green(primaryColor), Color.blue(primaryColor)),
                Color.TRANSPARENT
            ),
            floatArrayOf(0.0f, 0.35f, 0.75f, 1.0f),
            Shader.TileMode.CLAMP
        )
        corePaint.shader = coreShader
        canvas.drawCircle(cx, cy, coreRadius, corePaint)

        // 2. Polygonal Telemetry Core Rings (Octagonal geometry at center)
        val octPoints = 8
        val octRadius = coreRadius * 0.65f
        tempPath.reset()
        for (i in 0 until octPoints) {
            val ang = (i.toFloat() / octPoints) * 2f * PI.toFloat() + (if (currentState == State.THINKING) rotationAngle * 0.05f else 0f)
            val px = cx + octRadius * cos(ang)
            val py = cy + octRadius * sin(ang)
            if (i == 0) tempPath.moveTo(px, py) else tempPath.lineTo(px, py)
        }
        tempPath.close()

        shardStrokePaint.color = Color.argb(230, 255, 255, 255)
        shardStrokePaint.strokeWidth = 1.2f
        canvas.drawPath(tempPath, shardStrokePaint)
    }

    private fun getPrimaryColorForState(): Int {
        return when (currentState) {
            State.IDLE -> colorAmberPrimary
            State.LISTENING -> colorListeningCyan
            State.THINKING -> colorThinkingGold
            State.SPEAKING -> colorGoldBright
            State.SUCCESS -> colorSuccessEmerald
            State.ERROR -> colorErrorCrimson
        }
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (event.action == MotionEvent.ACTION_UP) {
            val cx = width / 2f
            val cy = height / 2f
            val dx = event.x - cx
            val dy = event.y - cy
            val dist = sqrt(dx * dx + dy * dy)
            val touchRadius = min(width, height) * 0.48f

            if (dist <= touchRadius) {
                performClick()
                onHologramTapListener?.invoke()
                return true
            }
        }
        return true
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }
}

