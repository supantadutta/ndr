# Astra NDR sensor agent (F#). Parses Zeek/Suricata logs and posts to the brain.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props ./
COPY src/Astra.Shared/Astra.Shared.fsproj src/Astra.Shared/
COPY src/Astra.Sensor/Astra.Sensor.fsproj src/Astra.Sensor/
RUN dotnet restore src/Astra.Sensor/Astra.Sensor.fsproj
COPY src/Astra.Shared/ src/Astra.Shared/
COPY src/Astra.Sensor/ src/Astra.Sensor/
RUN dotnet publish src/Astra.Sensor/Astra.Sensor.fsproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/runtime:10.0 AS runtime
WORKDIR /app
COPY --from=build /app ./
# Mount real Zeek/Suricata logs at /logs in production; the lab profile bind-mounts samples.
ENTRYPOINT ["dotnet", "Astra.Sensor.dll"]
