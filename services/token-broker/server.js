import http from "node:http";
import { createApp } from "./src/app.js";
import { loadConfig } from "./src/config.js";
import { ProviderRegistry } from "./src/providers.js";
import { TokenStore } from "./src/store.js";
import { TokenService } from "./src/token-service.js";

function main() {
  const config = loadConfig();
  const providers = new ProviderRegistry({ file: config.providersFile });
  const store = new TokenStore({
    filename: config.databasePath,
    encryptionKey: config.encryptionKey,
  });

  const purged = store.purgeExpiredStates();
  if (purged > 0) {
    console.log(`token-broker: purged ${purged} expired authorization state(s)`);
  }

  const purgeTimer = setInterval(() => {
    try {
      store.purgeExpiredStates();
    } catch (err) {
      console.error(`token-broker: state purge failed: ${err.message}`);
    }
    purgeRetention();
  }, 10 * 60 * 1000);
  purgeTimer.unref();

  // Optional retention: paused connections only, never an active
  // delegation. retentionDays = 0 (default) disables it entirely.
  function purgeRetention() {
    if (!config.retentionDays) return;
    try {
      const cutoff =
        Date.now() - config.retentionDays * 24 * 60 * 60 * 1000;
      const removed = store.purgePausedBefore(cutoff);
      if (removed > 0) {
        console.log(
          `token-broker: retention purged ${removed} paused connection(s)`
        );
      }
    } catch (err) {
      console.error(`token-broker: retention purge failed: ${err.message}`);
    }
  }
  purgeRetention();

  const tokenService = new TokenService({ store, config });
  const app = createApp({ config, providers, store, tokenService });
  const server = http.createServer(app);

  server.listen(config.port, "0.0.0.0", () => {
    console.log(
      `token-broker listening on ${config.port} (${providers.listEnabled().length} provider(s) enabled)`
    );
  });

  let shuttingDown = false;
  function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`token-broker: ${signal}, shutting down`);

    const timer = setTimeout(() => {
      console.error("token-broker: shutdown timed out");
      process.exit(1);
    }, 10_000);
    timer.unref();

    server.close(() => {
      clearInterval(purgeTimer);
      store.close();
      clearTimeout(timer);
      process.exit(0);
    });
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

try {
  main();
} catch (err) {
  console.error(`token-broker failed to start: ${err.message}`);
  process.exit(1);
}
