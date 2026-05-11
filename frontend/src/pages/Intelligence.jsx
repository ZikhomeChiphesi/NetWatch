import { useEffect, useState } from "react";
import API from "../services/api";

function Intelligence() {

  const [intel, setIntel] = useState(null);

  useEffect(() => {
    API.get("/intelligence")
      .then(res => setIntel(res.data))
      .catch(console.error);
  }, []);

  return (
    <div>

      <h1 className="text-3xl font-bold mb-6">
        Intelligence
      </h1>

      <div className="bg-white/5 border border-white/10 rounded-xl p-6">

        <p>
          Device Count: {intel?.device_count}
        </p>

        <p>
          Avg Risk: {intel?.avg_risk?.toFixed(2)}
        </p>

      </div>

    </div>
  );
}

export default Intelligence;