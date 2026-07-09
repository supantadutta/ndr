module Astra.Server.Json

open System.Text.Json
open System.Text.Json.Serialization

/// Single JSON policy for the whole API surface. DTOs are primitive-only
/// records, so this stays trivially compatible with the Thoth.Json decoders
/// used by the Fable client (camelCase everywhere).
let options =
    let o = JsonSerializerOptions(PropertyNamingPolicy = JsonNamingPolicy.CamelCase)
    o.Converters.Add(
        JsonFSharpConverter(
            unionEncoding =
                (JsonUnionEncoding.ExternalTag
                 ||| JsonUnionEncoding.UnwrapOption
                 ||| JsonUnionEncoding.UnwrapFieldlessTags
                 ||| JsonUnionEncoding.UnwrapSingleCaseUnions)))
    o

let serialize (value: 'T) = JsonSerializer.Serialize(value, options)
let deserialize<'T> (json: string) = JsonSerializer.Deserialize<'T>(json, options)
