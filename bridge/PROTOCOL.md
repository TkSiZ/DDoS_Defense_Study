# Protocolo da ponte entre o substrato e os agentes

O substrato (soak sintético ou controlador os-ken, em Python) mede o tráfego e
aplica as mitigações; a camada de agentes (JADE/BDI4JADE, em Java) decide. As
medidas são calculadas uma vez só, em `detection_core.py`, e entregues iguais
às três arquiteturas: o que muda entre elas é apenas o agente.

## Transporte

- TCP com JSON Lines: um objeto JSON por linha, terminado em `\n`.
- A camada de agentes é o servidor (porta padrão `7070`); o substrato conecta.
- Uma conexão por execução. Os domínios `0..N-1` são as bordas e `N` é o central.

## Do substrato para os agentes

`features`: as medidas de um domínio em uma janela.

```json
{"type":"features","tick":21,"domain":0,
 "f":{"pps":1333,"src_entropy":7.9,"dst_entropy":0.1,"src_rise":3.0,
      "dst_drop":3.4,"over_usage":true,"anomalous_usage":true,
      "fanin":488,"zscore":96.9,"threat":true,"target_ip":"10.0.0.99"}}
```

`reset`: início de um experimento; os agentes zeram o estado.

```json
{"type":"reset","run":"soak"}
```

Usados nos testes de falha: `kill` encerra o agente de um domínio, `spawn` o
recria e `switch_state` informa a quem assumiu um switch quais regras já
estão instaladas nele.

```json
{"type":"kill","domain":0}
{"type":"spawn","domain":0}
{"type":"switch_state","domain":0,"targets":["10.0.0.99"]}
```

## Dos agentes para o substrato

`decision`: ação a aplicar no switch `domain`. `action` é `MITIGATE` ou
`RESTORE`; `strategy` é `drop`, `rate_limit` ou `scrubbing`; `cause` é `local`
(detecção do próprio agente) ou `peer` (alerta de um vizinho).

```json
{"type":"decision","ts_ms":1792881635161,"tick":21,"domain":0,"agent":0,
 "target":"10.0.0.99","action":"MITIGATE","strategy":"drop","cause":"local"}
```

`telemetry`: contagem acumulada de mensagens FIPA-ACL, enviada a cada 500 ms,
e aviso de que um agente assumiu o switch de outro.

```json
{"type":"telemetry","ts_ms":1792881635161,"acl_msgs":11}
{"type":"telemetry","ts_ms":1792881635161,"event":"adopted","domain":2,"by":0,"acl_msgs":14}
```

## Quem faz o quê

| Camada | Faz | Não faz |
|---|---|---|
| Substrato | mede o tráfego, calcula as medidas, instala e remove as mitigações | não decide |
| Agentes | decidem (ECA ou BDI), trocam alertas FIPA-ACL e negociam por Contract Net | não falam OpenFlow |

Como os agentes rodam de fato no JADE, a latência de decisão, as mensagens
trocadas e a recuperação de falhas são medidas na execução, e não modeladas.
