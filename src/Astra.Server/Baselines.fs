module Astra.Server.Baselines

open System

/// ============================================================================
/// Behavioral baseline engine — statistical models first.
///
/// These are pure, unit-testable functions plus a small stateful accumulator
/// per (scope, metric). The detection engine queries baselines to judge whether
/// an observed value is anomalous relative to learned normal behavior. ML models
/// (unsupervised/sequence/graph) can be added later behind the same interface.
/// ============================================================================

// ---------------------------------------------------------------------------
// Pure statistical primitives
// ---------------------------------------------------------------------------

let mean (xs: float list) =
    match xs with [] -> 0.0 | _ -> List.sum xs / float xs.Length

let variance (xs: float list) =
    match xs with
    | [] | [_] -> 0.0
    | _ ->
        let m = mean xs
        (xs |> List.sumBy (fun x -> (x - m) ** 2.0)) / float (xs.Length - 1)

let stddev xs = sqrt (variance xs)

/// Classic z-score: (x - mean) / stddev.
let zScore (xs: float list) (x: float) =
    let s = stddev xs
    if s = 0.0 then 0.0 else (x - mean xs) / s

let median (xs: float list) =
    match xs with
    | [] -> 0.0
    | _ ->
        let sorted = List.sort xs
        let n = sorted.Length
        if n % 2 = 1 then sorted.[n / 2]
        else (sorted.[n / 2 - 1] + sorted.[n / 2]) / 2.0

/// Median absolute deviation — robust to outliers.
let mad (xs: float list) =
    match xs with
    | [] -> 0.0
    | _ ->
        let med = median xs
        median (xs |> List.map (fun x -> abs (x - med)))

/// Robust z-score using median + MAD (0.6745 scales MAD to σ for normal data).
let robustZScore (xs: float list) (x: float) =
    let m = mad xs
    if m = 0.0 then 0.0 else 0.6745 * (x - median xs) / m

/// Percentile (linear interpolation), p in [0,100].
let percentile (p: float) (xs: float list) =
    match xs with
    | [] -> 0.0
    | _ ->
        let sorted = List.sort xs
        let rank = (p / 100.0) * float (sorted.Length - 1)
        let lo = int (floor rank)
        let hi = int (ceil rank)
        if lo = hi then sorted.[lo]
        else
            let frac = rank - float lo
            sorted.[lo] * (1.0 - frac) + sorted.[hi] * frac

/// Frequency rarity in [0,1]: how rare `value` is among observations
/// (1 = never seen before, →0 = very common).
let frequencyRarity (observations: string list) (value: string) =
    match observations with
    | [] -> 1.0
    | _ ->
        let count = observations |> List.filter ((=) value) |> List.length
        1.0 - (float count / float observations.Length)

// ---------------------------------------------------------------------------
// Exponential moving average / variance accumulator (streaming state)
// ---------------------------------------------------------------------------

/// Streaming EMA with EMA-variance and decay. Suitable for per-entity metrics
/// updated as events arrive; `alpha` controls responsiveness / forgetting.
type EwmaState =
    { Mean: float
      Variance: float
      Count: int64
      Alpha: float }

module Ewma =
    let create alpha = { Mean = 0.0; Variance = 0.0; Count = 0L; Alpha = alpha }

    let update (s: EwmaState) (x: float) =
        if s.Count = 0L then
            { s with Mean = x; Variance = 0.0; Count = 1L }
        else
            let delta = x - s.Mean
            let newMean = s.Mean + s.Alpha * delta
            // EWMA of squared deviation (West's incremental variance, decayed)
            let newVar = (1.0 - s.Alpha) * (s.Variance + s.Alpha * delta * delta)
            { s with Mean = newMean; Variance = newVar; Count = s.Count + 1L }

    let stddev (s: EwmaState) = sqrt s.Variance

    /// z-score of x against the current EWMA mean/stddev.
    let zScore (s: EwmaState) (x: float) =
        let sd = stddev s
        if sd = 0.0 then 0.0 else (x - s.Mean) / sd

// ---------------------------------------------------------------------------
// Time-of-day / day-of-week baselines
// ---------------------------------------------------------------------------

/// Whether an hour is within a learned active-hours set (24-slot histogram).
type HourHistogram = int[]   // length 24, counts per hour

module HourHistogram =
    let empty : HourHistogram = Array.zeroCreate 24
    let add (h: HourHistogram) (at: DateTimeOffset) =
        let hh = Array.copy h
        hh.[at.Hour] <- hh.[at.Hour] + 1
        hh
    /// True if activity at `at` falls in an hour that is rarely/never active,
    /// given a minimum observation threshold.
    let isOffHours (h: HourHistogram) (at: DateTimeOffset) =
        let total = Array.sum h
        if total < 20 then false   // not enough history to judge
        else float h.[at.Hour] / float total < 0.01

// ---------------------------------------------------------------------------
// Baseline verdict (what the detection engine consumes)
// ---------------------------------------------------------------------------

type AnomalyVerdict =
    { IsAnomalous: bool
      Score: float            // robust z-score or rarity, higher = more anomalous
      Baseline: string        // human description of the learned normal
      Observed: string }

/// Judge a numeric observation against a sample using robust z-score.
let judgeNumeric (sample: float list) (observed: float) (threshold: float) (metric: string) : AnomalyVerdict =
    let z = robustZScore sample observed
    { IsAnomalous = abs z >= threshold && sample.Length >= 5
      Score = abs z
      Baseline = sprintf "%s median %.1f (MAD %.1f, n=%d)" metric (median sample) (mad sample) sample.Length
      Observed = sprintf "%.1f (robust z=%.1f)" observed z }
