# Defesa contra DDoS volumétrico com sistemas multiagentes: ECA, BDI e híbrida

Código do Trabalho de Conclusão de Curso (Sistemas de Informação, EST/UEA, 2026):
implementação e avaliação empírica de três arquiteturas multiagentes para
detecção e mitigação de ataques DDoS volumétricos em Redes Definidas por Software.

- **ECA**: todos os agentes reativos (Evento-Condição-Ação)
- **BDI**: todos os agentes deliberativos (BDI4JADE)
- **Híbrida**: agentes reativos nas bordas e deliberativo no central

## Arquitetura

Topologia em estrela: N switches de borda, por onde o tráfego entra, e um switch
central junto da vítima, que vê o que as bordas deixaram passar (defesa em
profundidade). Há um agente por switch e nenhum coordenador: cada agente decide
sozinho e troca alertas FIPA-ACL com os demais.

| Arquitetura | Bordas | Central |
|---|---|---|
| ECA | ECA | ECA |
| BDI | BDI (BDI4JADE) | BDI |
| Híbrida | ECA | BDI |

- Um agente que detecta um ataque mitiga no próprio switch e alerta os vizinhos.
  O ECA atende alertas por regra (limita a taxa); o BDI usa o alerta como evidência.
- Se um agente cai (aviso do AMS do JADE), outro assume o switch dele: no ECA e na
  híbrida, a próxima borda viva; no BDI, quem vencer o Contract Net.

```
  agentes (Java, jade/)          substrato (Python)
  borda 0 ... borda N-1   <-->   detection_core.py  medidas por janela
  central                 ponte  scenarios.py       tráfego sintético (estrela)
                          TCP    ddos_controller.py controlador os-ken (OpenFlow 1.3)
                                 mininet_*.py       rede emulada
```

O protocolo entre as camadas está em `bridge/PROTOCOL.md`.

## Arquivos

| Arquivo | Papel |
|---|---|
| `detection_core.py` | medidas de detecção (volume, entropia, fan-in, z-score) |
| `scenarios.py` | gerador de tráfego com verdade-terra: 9 vetores, picos legítimos, efeito da mitigação |
| `soak_24h.py` | experimento: as 3 arquiteturas em paralelo, recebendo o mesmo tráfego |
| `experimentos.sh` | todas as rodadas do plano experimental |
| `jade_runner.py` | sobe e derruba a camada de agentes |
| `ddos_controller.py` | controlador os-ken que entrega as features aos agentes e aplica as decisões |
| `mininet_topology.py`, `mininet_auto.py`, `overnight.sh` | rede emulada |
| `validacao_mininet.sh`, `validacao_mininet.py` | validação de ponta a ponta das três arquiteturas no Mininet |
| `bridge/` | protocolo e cliente da ponte |
| `jade/` | agentes JADE/BDI4JADE |

## Requisitos

- JDK 11+ (testado no 17)
- Python 3.10 com `pip install -r requirements.txt`
- Para o testbed emulado: Mininet, Open vSwitch >= 2.8 e hping3 (no Python do sistema, como root)

## Como rodar

Compilar os agentes (baixa JADE, org.json e commons-logging do Maven Central;
o `bdi4jade.jar` já vem em `jade/libs/`):

```bash
cd jade && ./build.sh
```

Experimentos (o soak sobe o JADE sozinho):

```bash
./experimentos.sh piloto      # 1 h
./experimentos.sh r1          # 24 h; ver o arquivo para as demais rodadas
```

Validação no Mininet (as três arquiteturas em sequência, cerca de 6 min cada;
resultados em `validacao/`):

```bash
sudo ./validacao_mininet.sh
```

Rede emulada à mão (três terminais):

```bash
cd jade && ./run.sh bdi 7070
REASONING_PORT=7070 osken-manager ddos_controller.py
sudo python3 mininet_auto.py --duration 3600
```

## Reprodutibilidade

Cada rodada grava em `soak_<tag>_meta.json` os parâmetros, a semente e o hash
dos arquivos usados. O código publicado aqui é posterior às rodadas da
monografia: inclui as correções da validação no Mininet e uma limpeza que não
altera as medidas nem o tráfego gerado para a mesma semente. Por isso os hashes
registrados nas rodadas não coincidem com os destes arquivos.

## Licenças de terceiros

BDI4JADE e JADE são distribuídos sob LGPL (ver `jade/libs/BDI4JADE-LICENSE`).
