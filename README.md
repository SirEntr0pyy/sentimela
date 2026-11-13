# Sentimela 0.5 — o Salvador fez um Hub. Nós trouxemos SSH.

> Centro de comando que cabe no terminal do telemóvel.
> O mapa do Salvador é bonito. O nosso cabe entre o teclado e a bateria a 7%.

Fork do [Sentinela de Salvador Pontes / teizinh](https://github.com/teizinh/sentinela):
honeypots e deteção de sondagens em Rust, com **central multi-host, journal
persistente e painel de terminal no mesmo executável**.

[Actions](https://github.com/SirEntr0pyy/sentimela/actions) ·
[Releases](https://github.com/SirEntr0pyy/sentimela/releases) ·
[Licença MIT](LICENSE)

## A competição teve uma atualização

O Salvador integrou as nossas melhorias de SSH, marquee linear, polling de
250 ms e builds multiplataforma no
[merge e625d89](https://github.com/teizinh/sentinela/commit/e625d8927429b01d9855d7112da8032fd8c79940).
Portanto, a tabela antiga já não servia para comparar com o original atual.
Ele respondeu com o [Sentinela Hub](https://github.com/teizinh/sentinela-hub).
Nós respondemos com **sentinela hub** e **sentinela watch**.

**Liderança mundial em irritar o Salvador sem sair do SSH.**
Classificação atribuída por um júri de uma pessoa que mantém este fork.

### O que muda de verdade

Comparação do código com o agente original em
[d57a463](https://github.com/teizinh/sentinela/commit/d57a463271a6fc37144d1510f7ee95e8b587a6a1)
e o Hub em
[1680da8](https://github.com/teizinh/sentinela-hub/commit/1680da8e42).
São referências fixas, não uma previsão do próximo contra-ataque.

| Prova | Sentinela + Hub do Salvador | Sentimela |
|---|---|---|
| Central no telemóvel por SSH | O agente tem TUI; o Hub é uma aplicação gráfica egui/eframe. | Agente, central sem interface gráfica e painel multi-host no mesmo binário. |
| Autenticação da central | O servidor de ingestão consultado não verifica credenciais. | Bearer token obrigatório para ingestão, saúde e leitura do histórico. |
| Bind inicial | Hub em 0.0.0.0:8765 por defeito. | 127.0.0.1:8765; exposição remota exige uma opção explícita. |
| Confirmação de gravação | O handler ignora o resultado da escrita na base de dados antes de responder sucesso. | Só confirma depois de write_all e sync_data; falhas devolvem erro HTTP. |
| Heartbeats do agente | Envio no arranque no código consultado. | No arranque e a cada 30 s; nós sem notícias há mais de 90 s aparecem offline. |
| Entrega de telemetria | Uma tarefa e um cliente HTTP por envio, sem repetição no emissor consultado. | Um worker e cliente reutilizados; fila de 256 eventos e até três tentativas para falhas transitórias. |
| Repetições de entrega | Sem deduplicação por identificador no handler consultado. | Deduplicação por nó e ID nos últimos 1024 eventos retidos. |
| Painel sem novidades | Hub gráfico com animações. | Poll de 1 s com ETag/304; sem corpo de histórico quando a revisão e a janela de atualização não mudam. |
| Armazenamento | SQLite WAL, adequado a consultas de histórico. | Journal JSONL até 64 MiB, reproduzido no arranque e legível com ferramentas de texto. |
| Visualização | Mapa, gráficos e interface de desktop. | Lista multi-host com pesquisa, detalhes, marquee e correlações; pensada para SSH. |

O original tem funcionalidades que este fork ainda não integra, incluindo o
mapa gráfico, honeyfiles e o detetor de DNS tunneling. A vantagem deste fork
está no fluxo de terminal e no controlo da entrega e dos recursos da central.
O Salvador continua a merecer os créditos. Infelizmente para a narrativa.

## Três modos, um executável

~~~bash
sentinela                         # Dashboard local e honeypots
sentinela hub --journal events.jsonl  # Central autenticada sem desktop
sentinela watch --hub http://127.0.0.1:8765  # Painel multi-host
~~~

A central só arranca com o subcomando **hub**. O agente só envia telemetria
quando configuras **--hub** ou **SENTINELA_HUB_URL**.

### 1. Preparar a central

Gera um token uma vez e guarda-o fora do repositório:

~~~bash
mkdir -p ~/.config/sentimela ~/.local/state/sentimela
(umask 077; openssl rand -hex 32 > ~/.config/sentimela/hub.token)
export SENTINELA_HUB_TOKEN="$(cat ~/.config/sentimela/hub.token)"

sentinela hub --bind 127.0.0.1:8765   --journal ~/.local/state/sentimela/events.jsonl
~~~

O servidor exige um token de 32 a 256 caracteres ASCII sem espaços. O journal novo é criado
com permissões 0600 em Unix. A API usa HTTP local; para acesso remoto usa um
túnel SSH ou um proxy HTTPS. Não há TLS nativo no servidor.

### 2. Ligar agentes

Na sessão do agente, configura **o mesmo token da central** e um ID estável:

~~~bash
export SENTINELA_HUB_TOKEN="$(cat ~/.config/sentimela/hub.token)"
sentinela --hub http://127.0.0.1:8765 --node-id vps-lisboa
~~~

Em máquinas diferentes, distribui o segredo de forma segura e cria um túnel:

~~~bash
ssh -N -L 8765:127.0.0.1:8765 utilizador@central
~~~

Depois usa http://127.0.0.1:8765 no agente ou painel desse computador.
Para um proxy remoto, usa https://central.exemplo. O cliente rejeita HTTP
fora de loopback, URLs com credenciais e redirecionamentos HTTP.

Também podes definir **SENTINELA_HUB_URL**, **SENTINELA_NODE_ID** e
**SENTINELA_NODE_NAME**. O envio é compatível com o formato de incidente plano do
Hub original; o nosso cliente também consegue enviá-lo para esse Hub, que
continua a ter as suas próprias condições de autenticação e persistência.
O agente original consultado não envia Bearer token e não se liga diretamente
à nossa API autenticada sem adaptar essa parte da integração.

### 3. Abrir o painel no telemóvel

Numa sessão SSH com TTY na central, carrega o token e abre:

~~~bash
export SENTINELA_HUB_TOKEN="$(cat ~/.config/sentimela/hub.token)"
sentinela watch --hub http://127.0.0.1:8765
~~~

**j / n / ↓** avançam, **p / ↑** recuam, **/** pesquisa, **Enter** abre o JSON
do incidente e **Esc** volta. **q** sai. Texto comprido faz marquee; só o incidente
selecionado anima. Se a ligação à API falhar, o painel conserva o último
snapshot e mostra o erro. Usa tmux para manter sessões entre reconexões SSH.

## Limites explícitos, para a competição não rebentar a RAM

| Recurso | Limite |
|---|---:|
| Workers assíncronos do runtime | 2 |
| Fila de deteções para o dashboard local | 1024 eventos |
| Fila de enriquecimento dos honeypots | 256 ligações já processadas pelo diálogo |
| Diálogos / enriquecimentos raw admitidos em simultâneo | 64, partilhados |
| Fila de envio do agente | 256 eventos |
| Tentativas HTTP por envio | Até 3; timeout de 3 s por tentativa |
| Pedidos autenticados em processamento na central | 64 |
| Corpo JSON por pedido | 16 KiB |
| Payload capturado por evento enviado à central | 2048 bytes |
| Nós apresentados pela central | 128 |
| Histórico de eventos retido em memória | 1024 |
| Eventos devolvidos em cada snapshot | 100 |
| Journal persistente | 64 MiB |
| Correlação multi-host | Mesmo IP em pelo menos 2 nós, nos eventos retidos dos últimos 10 min |

Quando uma fila enche, o trabalho adicional é recusado ou descartado em vez de
a fila crescer sem limite. O dashboard mostra **drop** e os contadores do envio
ao Hub no rodapé; o agente imprime-os ao sair. Payloads maiores que 2048 bytes
são enviados com truncagem assinalada; a captura original permanece no agente.
Eventos com outros metadados inválidos são contabilizados como descartados.

**Entrega com repetição limitada, não entrega garantida:** a fila do emissor
fica em RAM. Uma falha prolongada ou a saída do processo pode perder eventos.
Na saída há até cinco segundos para drenar a fila. Heartbeats e eventos
partilham o worker de envio; não há uma fila separada de heartbeats.

O limite de 64 pedidos aplica-se depois de os headers HTTP chegarem ao
middleware; não é uma promessa de resistência a qualquer ataque de rede.
A central destina-se a loopback / túnel SSH ou a um proxy configurado para
controlar ligações e TLS. Há um segredo partilhado, sem permissões por nó.

### Persistência e recuperação

Os eventos confirmados são escritos e sincronizados antes do HTTP 200.
O writer agrupa até 64 pedidos já em fila por sincronização. O arranque
reconstitui os contadores e o histórico recente; uma última linha incompleta é
removida. Corrupção numa linha completa impede o arranque e preserva o ficheiro.

Ao atingir 64 MiB, a central recusa novas gravações com HTTP 507.
Arquiva o journal com a central parada e arranca com um novo ficheiro. Não há
rotação automática nem limpeza silenciosa de histórico. Erros de escrita
colocam a ingestão em modo de falha até reiniciar. Heartbeats são presença
efémera; os eventos são persistentes. A API de saúde indica se o journal está
disponível para escrita.

A sincronização depende das garantias do sistema de ficheiros e do dispositivo;
não substitui backups. SIGKILL e falhas de energia continuam a existir,
apesar de o Salvador ter sido convidado a resolvê-los pessoalmente.

## O agente local continua a fazer o trabalho

- Honeypots TCP com interação de protocolos e captura de payload.
- Deteção raw de SYN e scans stealth em Linux, com CAP_NET_RAW.
- Pesquisa de incidentes, temas, GeoIP, rDNS e inspeção forense.
- Auto-ban configurável, whitelist, webhooks e exportação
  JSON / CSV / PCAP / CEF / Syslog / Markdown / HTML.
- Proteção SSH: whitelist inicial do cliente, killswitch indisponível nessa
  sessão e notificações desktop suprimidas.
- Marquee linear, preparação das linhas visíveis e polling de 250 ms em repouso.

As filas e a admissão estão limitadas; isso não significa que todas as
estruturas antigas tenham um limite global de memória. Estatísticas por IP,
caches e logs locais do agente têm as suas próprias políticas.

| Tecla | Ação no dashboard do agente |
|---|---|
| q / Ctrl+C | Sair |
| j / n / ↓, p / ↑ | Navegar |
| Enter | Inspecionar incidente |
| /, f | Pesquisa e filtro de severidade |
| b, u, x | Banir, whitelist e auto-ban |
| c, m, w | Sockets, métricas e auditor de portas |
| o, s, e | Abrir honeypot, simular e exportar |
| t, l, i | Tema, idioma e ajuda |
| k, r | Killswitch e restauro da rede em sessão local |

O inspetor de sockets lê /proc/net e é específico de Linux. Raw capture e
ações de firewall dependem da plataforma e das permissões. O painel watch
não executa bloqueios de firewall.

## Instalar e compilar

Os instaladores apontam para as [releases deste fork](https://github.com/SirEntr0pyy/sentimela/releases).
Novas funcionalidades só chegam a esses downloads depois de publicar uma
release com os respetivos pacotes.

~~~bash
# A partir deste repositório, com Rust stable e um compilador C
cargo build --release --locked
./target/release/sentinela --help
./target/release/sentinela hub --help
~~~

O binário usa thin LTO e remoção de símbolos. O tamanho depende da plataforma
e da toolchain; os 4,4 MiB medidos na versão anterior não são um benchmark desta.

Pacotes configurados: Linux x86_64 (.deb, .rpm, .tar.gz), Linux ARM64
(.deb, .tar.gz), macOS Intel / Apple Silicon (.tar.gz) e Windows x64
(.zip, instalador NSIS). O nome do executável continua a ser **sentinela**.

## Validação e releases

~~~bash
cargo test --locked
cargo build --release --locked
python3 scripts/test-mobile.py
python3 scripts/test-telemetry.py
~~~

Os testes cobrem autenticação HTTP, limites de corpo e fila, validação de
eventos, falha de escrita, recuperação de journal, deduplicação, correlação,
heartbeats repetidos e respostas 304. Os scripts Python exercitam o binário
real com pseudo-terminais, incluindo pesquisa, detalhes, resize e restauro.

Actions executa testes e builds para Linux, Windows e macOS. Os testes de
pseudo-terminal são de Linux. A release Apple Silicon é compilada num runner
Intel; não equivale a um teste de execução em ARM64.
Consulta o resultado efetivo de cada run no [Actions](https://github.com/SirEntr0pyy/sentimela/actions):
uma matriz configurada não significa que os runners estejam disponíveis.

Para publicar: atualiza Cargo.toml e Cargo.lock, faz commit e envia a tag
correspondente (**v0.5.0** para esta versão). O workflow testa, empacota e verifica
os checksums antes de publicar. Também aceita uma tag existente por execução
manual. Não publica automaticamente só por fazer push a main.

## Créditos

Projeto original por [Salvador Pontes / teizinh](https://github.com/teizinh).
Fork por [SirEntr0pyy](https://github.com/SirEntr0pyy).
A rivalidade é amigável. O código continua sob [MIT](LICENSE).
