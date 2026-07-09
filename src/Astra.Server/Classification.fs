module Astra.Server.Classification

open System
open System.Net
open Astra.Shared

/// CIDR-based internal/external classification driven by CoverageConfig.

type private Cidr = { Network: uint32; MaskBits: int }

let private parseCidr (s: string) : Cidr option =
    match s.Split('/') with
    | [| ip; bits |] ->
        match IPAddress.TryParse ip, Int32.TryParse bits with
        | (true, addr), (true, maskBits) when addr.AddressFamily = Sockets.AddressFamily.InterNetwork ->
            let bytes = addr.GetAddressBytes()
            let network =
                (uint32 bytes.[0] <<< 24) ||| (uint32 bytes.[1] <<< 16)
                ||| (uint32 bytes.[2] <<< 8) ||| uint32 bytes.[3]
            Some { Network = network; MaskBits = maskBits }
        | _ -> None
    | _ -> None

let private ipToUint (s: string) : uint32 option =
    match IPAddress.TryParse s with
    | true, addr when addr.AddressFamily = Sockets.AddressFamily.InterNetwork ->
        let b = addr.GetAddressBytes()
        Some ((uint32 b.[0] <<< 24) ||| (uint32 b.[1] <<< 16) ||| (uint32 b.[2] <<< 8) ||| uint32 b.[3])
    | _ -> None

let private inCidr (ip: uint32) (cidr: Cidr) =
    if cidr.MaskBits = 0 then true
    else
        let mask = ~~~((1u <<< (32 - cidr.MaskBits)) - 1u)
        (ip &&& mask) = (cidr.Network &&& mask)

type Classifier(config: CoverageConfig) =
    let internalCidrs = config.InternalCidrs |> List.choose parseCidr
    let excludedCidrs = config.ExcludedCidrs |> List.choose parseCidr
    let droppedCidrs = config.DroppedCidrs |> List.choose parseCidr

    member _.IsInternal(ip: string) =
        match ipToUint ip with
        | Some v -> internalCidrs |> List.exists (inCidr v)
        | None -> false   // IPv6 falls back to external until v6 CIDR support lands

    member _.IsExcluded(ip: string) =
        match ipToUint ip with
        | Some v -> excludedCidrs |> List.exists (inCidr v)
        | None -> false

    member _.IsDropped(ip: string) =
        match ipToUint ip with
        | Some v -> droppedCidrs |> List.exists (inCidr v)
        | None -> false

    member this.Direction(srcIp: string, dstIp: string) =
        match this.IsInternal srcIp, this.IsInternal dstIp with
        | true, true -> TrafficDirection.InternalToInternal
        | true, false -> TrafficDirection.InternalToExternal
        | false, true -> TrafficDirection.ExternalToInternal
        | false, false -> TrafficDirection.ExternalToExternal

    member this.Lane(srcIp: string, dstIp: string) =
        match this.Direction(srcIp, dstIp) with
        | TrafficDirection.InternalToInternal -> TrafficLane.EastWest
        | TrafficDirection.InternalToExternal
        | TrafficDirection.ExternalToInternal -> TrafficLane.NorthSouth
        | _ -> TrafficLane.Unknown
