# Astra NDR central brain (F# / Giraffe) - multi-stage build
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore first for layer caching
COPY Directory.Build.props ./
COPY src/Astra.Shared/Astra.Shared.fsproj src/Astra.Shared/
COPY src/Astra.Server/Astra.Server.fsproj src/Astra.Server/
RUN dotnet restore src/Astra.Server/Astra.Server.fsproj

# Build + publish
COPY src/Astra.Shared/ src/Astra.Shared/
COPY src/Astra.Server/ src/Astra.Server/
RUN dotnet publish src/Astra.Server/Astra.Server.fsproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app ./
# Ship the SQL migrations alongside the binary
COPY db/migrations /app/migrations
EXPOSE 5170
ENV ASPNETCORE_URLS=http://0.0.0.0:5170
ENTRYPOINT ["dotnet", "Astra.Server.dll"]
