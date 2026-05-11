import { useEffect, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";

import API from "../services/api";

function Topology() {

  const [graphData, setGraphData] = useState({
    nodes: [],
    links: []
  });

  // =========================
  // LOAD DEVICES
  // =========================
  const loadTopology = async () => {

    try {

      const res = await API.get("/devices");

      const devices = res.data;

      // MAIN ROUTER NODE
      const routerNode = {
        id: "NetWatch-Core",
        group: "core"
      };

      // DEVICE NODES
      const deviceNodes = devices.map((d, index) => ({
        id: d.ip || `device-${index}`,
        group: d.level || "LOW"
      }));

      // LINKS
      const links = devices.map((d, index) => ({
        source: "NetWatch-Core",
        target: d.ip || `device-${index}`
      }));

      setGraphData({
        nodes: [routerNode, ...deviceNodes],
        links
      });

    } catch (err) {
      console.error(err);
    }
  };

  // =========================
  // AUTO REFRESH
  // =========================
  useEffect(() => {

    loadTopology();

    const interval = setInterval(loadTopology, 5000);

    return () => clearInterval(interval);

  }, []);

  // =========================
  // NODE COLORS
  // =========================
  const getColor = (group) => {

    if (group === "core") return "#06b6d4";

    if (group === "HIGH") return "#ef4444";

    if (group === "MED") return "#facc15";

    return "#22c55e";
  };

  return (
    <div>

      {/* HEADER */}
      <div className="mb-6">

        <h1 className="text-4xl font-bold">
          Network Topology
        </h1>

        <p className="text-slate-400 mt-2">
          Real-time infrastructure visualization
        </p>

      </div>

      {/* GRAPH */}
      <div className="
        bg-white/5
        border border-white/10
        rounded-2xl
        overflow-hidden
      ">

        <ForceGraph2D
          graphData={graphData}
          height={700}
          backgroundColor="#0B1220"

          nodeLabel="id"

          nodeColor={(node) => getColor(node.group)}

          nodeCanvasObject={(node, ctx, globalScale) => {

            const label = node.id;

            const fontSize = 12 / globalScale;

            ctx.font = `${fontSize}px Sans-Serif`;

            ctx.fillStyle = getColor(node.group);

            ctx.beginPath();

            ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);

            ctx.fill();

            ctx.fillStyle = "white";

            ctx.fillText(
              label,
              node.x + 12,
              node.y + 4
            );
          }}
        />

      </div>

    </div>
  );
}

export default Topology;