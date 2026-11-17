# Camada de agentes (JADE / BDI4JADE)

Um agente por switch, sem coordenador: N agentes de borda (`local-0` a
`local-N-1`) e um agente central (`local-N`), junto da vítima.

| `--agent` | bordas | central |
|---|---|---|
| `eca` | `LocalEcaAgent` | `LocalEcaAgent` |
| `bdi` | `LocalBdiAgent` | `LocalBdiAgent` |
| `hybrid` | `LocalEcaAgent` | `LocalBdiAgent` |

## Classes

- `LocalEcaAgent`: regras fixas. Mitiga ao detectar e alerta os vizinhos; atende
  alertas limitando a taxa; assume o switch de um vizinho morto se for o sucessor.
- `LocalBdiAgent`: BDI4JADE. Crença de suspeita com decaimento, apoio dos
  vizinhos como evidência, objetivos `ProtectTarget`, `RestoreTarget` e
  `AdoptDomain`, planos drop / rate_limit / scrubbing; negocia quem assume um
  switch órfão por Contract Net (`jade.proto`).
- `PeerNetwork`: vizinhos vivos (AMS do JADE), alertas FIPA-ACL, domínios sob
  responsabilidade do agente e envio de decisões ao substrato.
- `AclCounter`: conta as mensagens trocadas entre agentes.
- `Bridge`: servidor TCP com o substrato (`../bridge/PROTOCOL.md`).
- `Launcher`: sobe os agentes, recria agentes derrubados e publica a contagem de mensagens.

## Compilar e rodar

Precisa de um JDK 11+. O `build.sh` baixa JADE, org.json e commons-logging do
Maven Central; o `bdi4jade.jar` já vem em `libs/` (não está no Central).

```bash
./build.sh
./run.sh bdi 7070 3        # arquitetura, porta, nº de bordas
```

Variáveis de ambiente: `BDI_DECAY`, `BDI_GOAL`, `BDI_RELEASE`, `BDI_DROP_CONF`,
`BDI_PEER` (parâmetros do BDI) e `MAS_COMMS=off` (desliga os alertas).
