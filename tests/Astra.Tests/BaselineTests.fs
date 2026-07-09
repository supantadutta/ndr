module Astra.Tests.BaselineTests

open System
open Xunit
open Astra.Server.Baselines

let private approx (expected: float) (actual: float) =
    Assert.True(abs (expected - actual) < 0.01, sprintf "expected ~%f got %f" expected actual)

[<Fact>]
let ``mean and stddev are correct`` () =
    let xs = [ 2.0; 4.0; 4.0; 4.0; 5.0; 5.0; 7.0; 9.0 ]
    approx 5.0 (mean xs)
    approx 2.138 (stddev xs)   // sample stddev

[<Fact>]
let ``median handles odd and even lengths`` () =
    approx 3.0 (median [ 1.0; 3.0; 5.0 ])
    approx 3.5 (median [ 1.0; 2.0; 5.0; 5.0 ])

[<Fact>]
let ``MAD is robust to an outlier`` () =
    let xs = [ 1.0; 1.0; 2.0; 2.0; 4.0; 100.0 ]
    // MAD stays small despite the 100 outlier
    Assert.True(mad xs < 3.0)

[<Fact>]
let ``robust z-score flags an outlier`` () =
    let sample = [ 10.0; 11.0; 9.0; 10.0; 12.0; 8.0; 10.0; 11.0 ]
    let z = robustZScore sample 40.0
    Assert.True(z > 3.5, sprintf "outlier should have high robust z, got %f" z)

[<Fact>]
let ``percentile interpolates`` () =
    let xs = [ for i in 1 .. 100 -> float i ]
    approx 50.5 (percentile 50.0 xs)
    Assert.True(percentile 95.0 xs >= 95.0)

[<Fact>]
let ``frequency rarity is 1 for unseen and lower for common`` () =
    let obs = [ "a"; "a"; "a"; "b" ]
    approx 1.0 (frequencyRarity obs "z")
    Assert.True(frequencyRarity obs "a" < 0.3)

[<Fact>]
let ``EWMA converges toward the stream mean`` () =
    let mutable s = Ewma.create 0.3
    for _ in 1 .. 50 do s <- Ewma.update s 100.0
    approx 100.0 s.Mean
    // a sudden spike yields a positive z-score
    Assert.True(Ewma.zScore s 200.0 > 1.0 || Ewma.stddev s = 0.0)

[<Fact>]
let ``judgeNumeric marks a clear anomaly`` () =
    let sample = [ 10.0; 11.0; 9.0; 10.0; 12.0; 8.0 ]
    let verdict = judgeNumeric sample 45.0 3.5 "test_metric"
    Assert.True(verdict.IsAnomalous)

[<Fact>]
let ``judgeNumeric stays calm within normal range`` () =
    let sample = [ 10.0; 11.0; 9.0; 10.0; 12.0; 8.0 ]
    let verdict = judgeNumeric sample 10.5 3.5 "test_metric"
    Assert.False(verdict.IsAnomalous)

[<Fact>]
let ``off-hours detection needs enough history`` () =
    let mutable h = HourHistogram.empty
    // build a 9-17 business-hours profile
    for _ in 1 .. 50 do
        for hour in 9 .. 17 do
            h <- HourHistogram.add h (DateTimeOffset(2026, 1, 1, hour, 0, 0, TimeSpan.Zero))
    let at3am = DateTimeOffset(2026, 1, 2, 3, 0, 0, TimeSpan.Zero)
    Assert.True(HourHistogram.isOffHours h at3am)
    let at10am = DateTimeOffset(2026, 1, 2, 10, 0, 0, TimeSpan.Zero)
    Assert.False(HourHistogram.isOffHours h at10am)
