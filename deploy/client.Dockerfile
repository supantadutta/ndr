# Astra NDR analyst console (Fable 5 -> JS, served by nginx)
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Node for Vite
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*

COPY Directory.Build.props .config/dotnet-tools.json ./
COPY .config/ ./.config/
RUN dotnet tool restore

COPY src/Astra.Shared/ src/Astra.Shared/
COPY src/Astra.Client/ src/Astra.Client/
WORKDIR /src/src/Astra.Client
RUN npm install
RUN dotnet fable --run vite build

FROM nginx:1.27-alpine AS runtime
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/src/Astra.Client/dist /usr/share/nginx/html
EXPOSE 80
