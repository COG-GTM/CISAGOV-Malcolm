# <a name="Running"></a>Running Malcolm

* [Running Malcolm](#Running)
    - [OpenSearch and Elasticsearch instances](opensearch-instances.md#OpenSearchInstance)
        + [Authentication and authorization for remote data store clusters](opensearch-instances.md#OpenSearchAuth)
    - [Starting Malcolm](#Starting)
    - [Stopping and restarting Malcolm](#StopAndRestart)
    - [Checking Malcolm's status](#Status)
    - [Clearing Malcolm's data](#Wipe)
    - [Temporary read-only interface](#ReadOnlyUI)

## <a name="Starting"></a>Starting Malcolm

[Docker compose](https://docs.docker.com/compose/) is used to coordinate running the containers. To start Malcolm, navigate to the directory containing `docker-compose.yml` and run:
```
$ ./scripts/start
```
This will create the containers' virtual network and instantiate them, then leave them running in the background. The Malcolm containers may take several minutes to start up completely. To follow the debug output for an already-running Malcolm instance, run:
```
$ ./scripts/logs
```
You can also use `docker stats` to monitor the resource utilization of running containers.

## <a name="StopAndRestart"></a>Stopping and restarting Malcolm

You can run `./scripts/stop` to stop the containers and remove their virtual network. Alternatively, `./scripts/restart` will restart an instance of Malcolm. Because the data on disk is stored on the host in bind-mounted volumes, performing these operations will not result in loss of data.

Malcolm can be configured to automatically restart when the Docker system daemon restarts (for example, on system reboot). This behavior depends on the [value](https://docs.docker.com/config/containers/start-containers-automatically/) of the [`restart:`](https://docs.docker.com/compose/compose-file/#restart) setting for each service in the `docker-compose.yml` file. This value can be set via the **Malcolm Restart Policy** option of [`./scripts/configure`](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems).

## <a name="Status"></a>Checking Malcolm's status

Run `./scripts/status` (or `./scripts/control.py --status`) to display the state of Malcolm's containers. For Docker Compose this is the output of `docker compose ps`; for Kubernetes it is a table of the cluster's nodes and of the pods in Malcolm's namespace.

For monitoring and scripting, add `--json` to get a single machine-readable JSON document on standard output instead of the human-readable table. The `--json` flag only applies to the status operation and cannot be combined with other operations. In this mode nothing other than the JSON document is written to standard output (log messages go to standard error), and the exit code reflects Malcolm's health:

* `0` – every service is running and, if it reports health, healthy
* `1` – at least one service is stopped, not yet created, or not healthy
* `2` – the status could not be collected (e.g., `docker compose ps` failed or returned unparseable output, the Kubernetes API could not be reached, or the Python Kubernetes client is not installed); the document then contains an `error` field

```
$ ./scripts/status --json
{
  "runtime": "docker_compose",
  "services": [
    {
      "name": "malcolm-api-1",
      "service": "api",
      "state": "running",
      "health": "healthy",
      "image": "ghcr.io/idaholab/malcolm/api",
      "image_tag": "{{ site.malcolm.version }}",
      "status": "Up 2 hours (healthy)"
    },
    ...
  ],
  "summary": {
    "total": 25,
    "running": 25,
    "unhealthy": 0,
    "stopped": 0,
    "healthy": true
  }
}
```

Each entry in `services` gives the container `name`, the compose `service` (or Kubernetes deployment) name, the container `state` (e.g., `running`, `exited`, or `not created` for a service defined for the active profile that has no container), its `health` (`healthy`, `unhealthy`, or `starting` when a health check is defined, otherwise `null`), the `image` repository and `image_tag`, and the runtime's human-readable `status` string. On Kubernetes each entry also includes the `container` name, `restarts` count, worker `node`, and pod `phase`, `health` is derived from the container's readiness, and a deployment present in the namespace that has no pods at all is reported as `not created` (deployments scaled to zero replicas are ignored). The `summary` object counts the `running`, `unhealthy` (running but not reporting healthy), and `stopped` (anything not running) services, and `healthy` is `true` only when `unhealthy` and `stopped` are both zero. The `-s`/`--service` argument limits the report to the named service(s). For example, a cron job or monitoring agent could run `./scripts/status --json > /var/tmp/malcolm-status.json || alert` to fail only when Malcolm is not fully healthy.

## <a name="Wipe"></a>Clearing Malcolm's data

Run `./scripts/wipe` to stop the Malcolm instance and wipe its OpenSearch database (**including** [index snapshots and management policies](index-management.md#IndexManagement) and [alerting configuration](alerting.md#Alerting)).

## <a name="ReadOnlyUI"></a>Temporary read-only interface

To temporarily set the Malcolm user interfaces into read-only configuration, run the following commands from the Malcolm installation directory.

First, to configure [Nginx](https://nginx.org/) to disable access to the upload and other interfaces for changing Malcolm settings, and to deny HTTP methods other than `GET` and `POST`:

```
docker compose exec nginx-proxy bash -c "cp /etc/nginx/nginx_readonly.conf /etc/nginx/nginx.conf && nginx -s reload"
```

Second, to set the existing OpenSearch data store to read-only:

```
docker compose exec dashboards-helper /usr/local/bin/opensearch_read_only.py -i _cluster
```

These commands must be re-run every time Malcolm is restarted.

Note: after running these commands there may be an increase of error messages in the Malcolm containers' output as various background processes will fail due to the read-only nature of the indices. Additionally, some features such as Arkime's [Hunt](arkime.md#ArkimeHunt) and [building your own visualizations and dashboards](dashboards.md#BuildDashboard) in OpenSearch Dashboards will not function correctly in read-only mode.