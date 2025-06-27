import { j as jsxRuntimeExports } from "./index-BYGq6Ng0.js";
import { r as reactExports, M as MapContainer, T as TileLayer, G as GeoJSON, u as useMap, R as React } from "./leaflet-vendor-BcXhkSxI.js";
import "./react-vendor-CSPBeBBz.js";
const brazilStatesData = {
  "type": "FeatureCollection",
  "features": [
    {
      "type": "Feature",
      "properties": {
        "id": "AC",
        "name": "Acre",
        "abbreviation": "AC",
        "region": "Norte",
        "capital": "Rio Branco",
        "coordinates": [-8.77, -70.55]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-73.18, -7.11],
          [-72.78, -7.53],
          [-72.64, -9.41],
          [-70.55, -9.5],
          [-69.57, -10.95],
          [-68.97, -11.02],
          [-69.64, -10.46],
          [-70.63, -9.77],
          [-71.3, -9.86],
          [-72.38, -9.49],
          [-73.2, -7.75],
          [-73.18, -7.11]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "AL",
        "name": "Alagoas",
        "abbreviation": "AL",
        "region": "Nordeste",
        "capital": "Maceió",
        "coordinates": [-9.71, -35.73]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-35.88, -8.91],
          [-35.48, -9.21],
          [-35.68, -9.66],
          [-36.34, -9.84],
          [-36.86, -10.28],
          [-37.05, -10],
          [-36.77, -9.61],
          [-36.39, -9.45],
          [-35.88, -8.91]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "AP",
        "name": "Amapá",
        "abbreviation": "AP",
        "region": "Norte",
        "capital": "Macapá",
        "coordinates": [0, -51]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-50.5, 2],
          [-50, 1],
          [-51, 0],
          [-52, 0.5],
          [-52.5, 2],
          [-51.5, 3],
          [-50.5, 2]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "AM",
        "name": "Amazonas",
        "abbreviation": "AM",
        "region": "Norte",
        "capital": "Manaus",
        "coordinates": [-3.07, -60.03]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-66, 1],
          [-65, -1],
          [-63, -3],
          [-60, -5],
          [-58, -3],
          [-59, -1],
          [-61, 1],
          [-66, 1]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "BA",
        "name": "Bahia",
        "abbreviation": "BA",
        "region": "Nordeste",
        "capital": "Salvador",
        "coordinates": [-12.96, -38.51]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-38.5, -9],
          [-37.5, -10],
          [-38, -13],
          [-39, -15],
          [-41, -14],
          [-42, -11],
          [-40, -9.5],
          [-38.5, -9]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "CE",
        "name": "Ceará",
        "abbreviation": "CE",
        "region": "Nordeste",
        "capital": "Fortaleza",
        "coordinates": [-3.71, -38.54]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-37.5, -3],
          [-38, -4],
          [-39, -5],
          [-40.5, -4.5],
          [-41, -3.5],
          [-40, -2.5],
          [-38.5, -3],
          [-37.5, -3]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "DF",
        "name": "Distrito Federal",
        "abbreviation": "DF",
        "region": "Centro-Oeste",
        "capital": "Brasília",
        "coordinates": [-15.83, -47.86]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-47.31, -15.5],
          [-47.31, -16.03],
          [-48.28, -16.04],
          [-48.28, -15.5],
          [-47.31, -15.5]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "ES",
        "name": "Espírito Santo",
        "abbreviation": "ES",
        "region": "Sudeste",
        "capital": "Vitória",
        "coordinates": [-20.32, -40.34]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-39.5, -18],
          [-40, -19],
          [-40.5, -20.5],
          [-41, -21],
          [-41, -20],
          [-40, -18.5],
          [-39.5, -18]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "GO",
        "name": "Goiás",
        "abbreviation": "GO",
        "region": "Centro-Oeste",
        "capital": "Goiânia",
        "coordinates": [-16.64, -49.31]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-46, -13],
          [-47, -14],
          [-49, -16],
          [-51, -18],
          [-52, -17],
          [-51, -15],
          [-49, -13],
          [-46, -13]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "MA",
        "name": "Maranhão",
        "abbreviation": "MA",
        "region": "Nordeste",
        "capital": "São Luís",
        "coordinates": [-2.55, -44.3]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-41.5, -1],
          [-42, -2.5],
          [-44, -3],
          [-45, -5],
          [-46, -7],
          [-45, -6],
          [-43, -4],
          [-41.5, -1]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "MT",
        "name": "Mato Grosso",
        "abbreviation": "MT",
        "region": "Centro-Oeste",
        "capital": "Cuiabá",
        "coordinates": [-15.6, -56.1]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-50, -8],
          [-52, -10],
          [-56, -11],
          [-58, -15],
          [-58, -18],
          [-55, -17],
          [-52, -14],
          [-50, -8]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "MS",
        "name": "Mato Grosso do Sul",
        "abbreviation": "MS",
        "region": "Centro-Oeste",
        "capital": "Campo Grande",
        "coordinates": [-20.51, -54.54]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-51, -18],
          [-52, -20],
          [-54, -22],
          [-56, -23],
          [-57, -22],
          [-56, -20],
          [-53, -18],
          [-51, -18]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "MG",
        "name": "Minas Gerais",
        "abbreviation": "MG",
        "region": "Sudeste",
        "capital": "Belo Horizonte",
        "coordinates": [-19.81, -43.95]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-41, -15],
          [-42, -16],
          [-44, -18],
          [-46, -20],
          [-48, -22],
          [-47, -21],
          [-45, -19],
          [-43, -17],
          [-41, -15]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "PA",
        "name": "Pará",
        "abbreviation": "PA",
        "region": "Norte",
        "capital": "Belém",
        "coordinates": [-1.46, -48.5]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-46, 0],
          [-48, -2],
          [-50, -4],
          [-54, -3],
          [-56, -1],
          [-54, 1],
          [-50, 2],
          [-46, 0]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "PB",
        "name": "Paraíba",
        "abbreviation": "PB",
        "region": "Nordeste",
        "capital": "João Pessoa",
        "coordinates": [-7.06, -35.55]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-34.5, -6],
          [-35, -7],
          [-36, -7.5],
          [-37, -7],
          [-36.5, -6.5],
          [-35.5, -6],
          [-34.5, -6]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "PR",
        "name": "Paraná",
        "abbreviation": "PR",
        "region": "Sul",
        "capital": "Curitiba",
        "coordinates": [-25.25, -49.23]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-48, -23],
          [-49, -24],
          [-51, -25],
          [-53, -26],
          [-54, -25],
          [-52, -23.5],
          [-50, -23],
          [-48, -23]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "PE",
        "name": "Pernambuco",
        "abbreviation": "PE",
        "region": "Nordeste",
        "capital": "Recife",
        "coordinates": [-8.28, -35.07]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-35, -7],
          [-35.5, -8],
          [-36, -8.5],
          [-38, -9],
          [-40, -8],
          [-39, -7.5],
          [-37, -7],
          [-35, -7]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "PI",
        "name": "Piauí",
        "abbreviation": "PI",
        "region": "Nordeste",
        "capital": "Teresina",
        "coordinates": [-5.2, -42.73]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-40.5, -3],
          [-41, -4],
          [-42, -6],
          [-43, -8],
          [-44, -10],
          [-45, -9],
          [-44, -7],
          [-42.5, -5],
          [-40.5, -3]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "RJ",
        "name": "Rio de Janeiro",
        "abbreviation": "RJ",
        "region": "Sudeste",
        "capital": "Rio de Janeiro",
        "coordinates": [-22.84, -43.15]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-41, -21],
          [-42, -22],
          [-43, -23],
          [-44.5, -23],
          [-44, -22],
          [-43, -21],
          [-41, -21]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "RN",
        "name": "Rio Grande do Norte",
        "abbreviation": "RN",
        "region": "Nordeste",
        "capital": "Natal",
        "coordinates": [-5.22, -36.52]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-35, -5],
          [-36, -5.5],
          [-37, -6],
          [-38, -5.5],
          [-37, -5],
          [-36, -4.5],
          [-35, -5]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "RS",
        "name": "Rio Grande do Sul",
        "abbreviation": "RS",
        "region": "Sul",
        "capital": "Porto Alegre",
        "coordinates": [-30.01, -51.22]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-49.5, -27],
          [-50, -28],
          [-52, -30],
          [-54, -31],
          [-56, -30],
          [-55, -28],
          [-53, -27],
          [-49.5, -27]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "RO",
        "name": "Rondônia",
        "abbreviation": "RO",
        "region": "Norte",
        "capital": "Porto Velho",
        "coordinates": [-8.83, -63.9]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-60, -8],
          [-62, -9],
          [-64, -11],
          [-65, -12],
          [-64, -13],
          [-62, -12],
          [-60, -10],
          [-60, -8]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "RR",
        "name": "Roraima",
        "abbreviation": "RR",
        "region": "Norte",
        "capital": "Boa Vista",
        "coordinates": [2.73, -60.67]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-58, 1],
          [-59, 2],
          [-61, 3],
          [-63, 4],
          [-62, 3],
          [-60, 2],
          [-58, 1]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "SC",
        "name": "Santa Catarina",
        "abbreviation": "SC",
        "region": "Sul",
        "capital": "Florianópolis",
        "coordinates": [-27.33, -49.44]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-48.5, -26],
          [-49, -27],
          [-50, -28],
          [-52, -28.5],
          [-53, -27.5],
          [-51, -26.5],
          [-49.5, -26],
          [-48.5, -26]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "SP",
        "name": "São Paulo",
        "abbreviation": "SP",
        "region": "Sudeste",
        "capital": "São Paulo",
        "coordinates": [-23.55, -46.64]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-44, -20],
          [-46, -21],
          [-48, -23],
          [-50, -24],
          [-51, -23],
          [-49, -21],
          [-47, -20],
          [-44, -20]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "SE",
        "name": "Sergipe",
        "abbreviation": "SE",
        "region": "Nordeste",
        "capital": "Aracaju",
        "coordinates": [-10.9, -37.07]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-36.5, -10],
          [-37, -10.5],
          [-37.5, -11],
          [-37, -11.5],
          [-36.5, -11],
          [-36.5, -10]
        ]]
      }
    },
    {
      "type": "Feature",
      "properties": {
        "id": "TO",
        "name": "Tocantins",
        "abbreviation": "TO",
        "region": "Norte",
        "capital": "Palmas",
        "coordinates": [-10.25, -48.25]
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [[
          [-46, -6],
          [-47, -8],
          [-48, -10],
          [-49, -12],
          [-48, -13],
          [-47, -11],
          [-46, -9],
          [-46, -6]
        ]]
      }
    }
  ]
};
const AccessibleMap = ({ documents, onStateSelect, selectedState }) => {
  const stateDocumentCounts = documents.reduce((acc, doc) => {
    if (doc.state) {
      acc[doc.state] = (acc[doc.state] || 0) + 1;
    }
    return acc;
  }, {});
  const handleStateSelection = (stateId) => {
    onStateSelect(stateId);
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "accessible-map", role: "application", "aria-label": "Interactive map of Brazilian states with legislation data", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "map-heading", children: "Brazilian States Legislative Data" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sr-only", "aria-live": "polite", id: "map-status", children: selectedState ? `Selected state: ${selectedState}` : "No state selected" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "group", "aria-labelledby": "map-heading", children: Object.entries(stateDocumentCounts).map(([stateId, count]) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        className: `state-button ${selectedState === stateId ? "selected" : ""}`,
        onClick: () => handleStateSelection(stateId),
        "aria-pressed": Boolean(selectedState === stateId),
        "aria-describedby": `${stateId}-info`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "state-name", children: stateId }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "state-count", id: `${stateId}-info`, children: [
            count,
            " ",
            count === 1 ? "document" : "documents"
          ] })
        ]
      },
      stateId
    )) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-interface", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "state-select", children: "Select state:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          id: "state-select",
          value: selectedState || "",
          onChange: (e) => handleStateSelection(e.target.value),
          "aria-describedby": "state-select-help",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "All states" }),
            Object.keys(stateDocumentCounts).map((stateId) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: stateId, children: [
              stateId,
              " (",
              stateDocumentCounts[stateId],
              " documents)"
            ] }, stateId))
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "state-select-help", className: "help-text", children: "Choose a Brazilian state to filter legislation documents" })
    ] })
  ] });
};
const MapController = reactExports.memo(({ center, zoom }) => {
  const map = useMap();
  React.useEffect(() => {
    map.setView(center, zoom);
  }, [center, zoom, map]);
  return null;
});
MapController.displayName = "MapController";
const OptimizedMap = reactExports.memo(({
  selectedState,
  selectedMunicipality,
  documents,
  onLocationClick,
  highlightedLocations = []
}) => {
  const memoizedDocuments = reactExports.useMemo(
    () => documents.filter((doc) => doc.state),
    [documents]
  );
  reactExports.useMemo(
    () => memoizedDocuments.reduce((acc, doc) => {
      if (doc.state) acc[doc.state] = (acc[doc.state] || 0) + 1;
      return acc;
    }, {}),
    [memoizedDocuments]
  );
  const [mapCenter, mapZoom] = reactExports.useMemo(() => {
    var _a;
    if (selectedState) {
      const stateData = brazilStatesData.features.find(
        (feature) => feature.properties.id === selectedState
      );
      if ((_a = stateData == null ? void 0 : stateData.properties) == null ? void 0 : _a.coordinates) {
        return [stateData.properties.coordinates, 6];
      }
    }
    return [[-15.7801, -47.9292], 4];
  }, [selectedState]);
  const getStateStyle = reactExports.useCallback((feature) => {
    if (!feature) {
      return {};
    }
    const stateId = feature.properties.id;
    const isSelected = selectedState === stateId;
    const isHighlighted = highlightedLocations.includes(stateId);
    return {
      fillColor: isSelected ? "#2196F3" : isHighlighted ? "#FFC107" : "#4CAF50",
      weight: isSelected ? 3 : 2,
      opacity: 1,
      color: "white",
      dashArray: isSelected ? "" : "3",
      fillOpacity: isSelected ? 0.9 : isHighlighted ? 0.7 : 0.5
    };
  }, [selectedState, highlightedLocations]);
  const handleLocationClick = reactExports.useCallback((type, id) => {
    onLocationClick(type, id);
  }, [onLocationClick]);
  const onEachState = reactExports.useCallback((feature, layer) => {
    if (feature.properties && feature.properties.name) {
      const stateData = feature.properties;
      const stateDocuments = memoizedDocuments.filter((doc) => doc.state === stateData.abbreviation);
      layer.bindPopup(`
        <div style="min-width: 200px;">
          <h3>${stateData.name} (${stateData.abbreviation})</h3>
          <p><strong>Capital:</strong> ${stateData.capital}</p>
          <p><strong>Região:</strong> ${stateData.region}</p>
          <p><strong>Documentos:</strong> ${stateDocuments.length}</p>
        </div>
      `);
      layer.on({
        mouseover: (e) => {
          const targetLayer = e.target;
          targetLayer.setStyle({
            weight: 5,
            color: "#666",
            dashArray: "",
            fillOpacity: 0.7
          });
          targetLayer.bringToFront();
        },
        mouseout: (e) => {
          const targetLayer = e.target;
          targetLayer.setStyle(getStateStyle(feature));
        },
        click: () => {
          handleLocationClick("state", stateData.id);
        }
      });
    }
  }, [memoizedDocuments, getStateStyle, handleLocationClick]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "map-wrapper", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: "visual-map",
        role: "img",
        "aria-label": "Interactive map of Brazil showing legislative data by state",
        "aria-describedby": "map-description",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "map-description", className: "sr-only", children: "This map shows Brazilian states with different colors indicating legislative document availability. Use the accessible interface below for keyboard navigation." }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "map-container map-controls", style: { height: "100%", width: "100%" }, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs(
              MapContainer,
              {
                center: mapCenter,
                zoom: mapZoom,
                style: { height: "100%", width: "100%" },
                zoomControl: true,
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    TileLayer,
                    {
                      attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
                      url: "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                    }
                  ),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(MapController, { center: mapCenter, zoom: mapZoom }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    GeoJSON,
                    {
                      data: brazilStatesData,
                      style: getStateStyle,
                      onEachFeature: onEachState
                    }
                  )
                ]
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "map-legend", style: {
              position: "absolute",
              bottom: "20px",
              right: "20px",
              background: "rgba(255, 255, 255, 0.95)",
              padding: "12px",
              borderRadius: "8px",
              boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
              fontSize: "12px",
              lineHeight: "1.4",
              zIndex: 1e3
            }, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { style: { fontWeight: "bold", marginBottom: "8px" }, children: "Legenda" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { style: { display: "flex", alignItems: "center", marginBottom: "4px" }, children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { style: {
                  width: "16px",
                  height: "16px",
                  backgroundColor: "#2196F3",
                  marginRight: "8px",
                  border: "1px solid #fff"
                } }),
                "Estado selecionado"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { style: { display: "flex", alignItems: "center", marginBottom: "4px" }, children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { style: {
                  width: "16px",
                  height: "16px",
                  backgroundColor: "#FFC107",
                  marginRight: "8px",
                  border: "1px solid #fff"
                } }),
                "Estados destacados"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { style: { display: "flex", alignItems: "center" }, children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("div", { style: {
                  width: "16px",
                  height: "16px",
                  backgroundColor: "#4CAF50",
                  marginRight: "8px",
                  border: "1px solid #fff"
                } }),
                "Estados com documentos"
              ] })
            ] })
          ] })
        ]
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      AccessibleMap,
      {
        documents: memoizedDocuments,
        onStateSelect: (stateId) => handleLocationClick("state", stateId),
        selectedState
      }
    )
  ] });
});
OptimizedMap.displayName = "OptimizedMap";
var OptimizedMap_default = OptimizedMap;
export {
  OptimizedMap,
  OptimizedMap_default as default
};
