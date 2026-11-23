# Evidências — Teste exploratório da página/formulário de suporte

Equipe Control-Z · Matheus Eiki · 22/11/2026
Funcionalidade: `/support` + `POST /api/support` · Ambiente: `localhost:3000`, banco SQLite isolado (fora do repositório).

> **CTF.** A aplicação é propositalmente vulnerável. Estas evidências **registram** o comportamento; não corrigem nada. Todos os valores de FLAG foram **redigidos** (`OSS{__FLAG_REDIGIDA__}`).

## Capturas

| Arquivo                            | O que mostra                                                                                          |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `01-pagina-suporte.jpg`            | Página de suporte (hero + convite ao assistente de IA).                                               |
| `02-formulario-topo.jpg`           | Formulário: Email, Title, Description.                                                                |
| `03-formulario-upload-morto.jpg`   | Campo "Upload Screenshot" com aviso _"not currently processed"_ (D-05).                               |
| `04-sucesso-resumo.jpg`            | Tela de sucesso com o _Request Summary_ (fluxo feliz, E1).                                            |
| `05-ssrf-externo-renderizado.jpg`  | SSRF: conteúdo de `example.com` buscado pelo servidor e renderizado (E5 / D-01).                      |
| `06-internal-redireciona-home.jpg` | `/internal` acessado direto no navegador redireciona para a home (guarda só do lado do cliente, NC2). |
| `07-sink-html-truncado-vazio.jpg`  | Caixa vazia por truncamento no `#` de uma URL `data:` (NC1).                                          |
| `08-sink-html-renderizado.jpg`     | Sink de HTML: `<div>` injetado renderizado via `dangerouslySetInnerHTML` (E8 / D-02).                 |

## Logs

| Arquivo            | O que contém                                                                                                                                                                                    |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api-sessao.log`   | Cenários S-API-1..9 contra `POST /api/support` (flags redigidas): fluxo feliz, e-mail inválido, campos vazios/ausentes, SSRF externo/interno, esquema `file:`, sink de HTML e teste de tamanho. |
| `servidor-log.txt` | Trecho do log do Next.js (dev) com os status por requisição durante a sessão.                                                                                                                   |

## Como foi gerado

- App iniciado com `DATABASE_URL` apontando para um banco isolado no diretório temporário da sessão — o `prisma/dev.db` do repositório **não** foi tocado.
- Capturas de tela pelo navegador embutido; chamadas de API via `curl`, com os valores de FLAG mascarados por `sed` antes da gravação.
- Payloads de segurança mantidos **benignos** (um `<div>` estilizado, sem script) apenas para evidenciar o defeito de renderização.
