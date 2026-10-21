# Logs workspace

The complete frontend implementation is in `web/index.html`. CSS and JavaScript
stay inline because the existing backend serves this file at `/`. No additional
static routes, API parameters, dependencies, or database changes are required.

## Component structure

| Component | Responsibility |
| --- | --- |
| Logs filter toolbar | Source, file type, category, keyword search, received-time range, telemetry visibility |
| `LogsWorkspace` | URL state, API paging, selection, telemetry grouping, keyboard controls and inspector lifecycle |
| Master table | Sticky column header, its own scroll container, short timestamps, selected rows and expandable telemetry groups |
| Splitter | Pointer and keyboard resizing; width saved in localStorage |
| Event inspector | Compact title/status header, action buttons and four accessible tabs |
| `LogsJSONTree` | Lazy JSON disclosure nodes, key/value search, expand/collapse and empty-field handling |
| Pagination footer | Latest / Previous / Older and 25 / 50 / 100 entries per page |

## Layout and interaction

- The filter toolbar starts directly below the global Logs header. There is no
  duplicate page heading or theme switch.
- The inspector header contains the event title, source/status badges and actions.
  Event time, agent, rule and MITRE metadata appear once in Overview.

- At 1200 CSS pixels and above, the table and inspector share the viewport, with
  an initial 58% table width. Drag the splitter or use its Left/Right keys.
  Home/End move it to the supported minimum/maximum (35% / 75%).
- Below 1200px, clicking an entry opens a right-side inspector drawer. Close it
  using its Close button, the backdrop, or Escape. Enter on a selected table row
  opens the drawer; Enter on a non-interactive area of the drawer closes it.
- The Logs view locks document scrolling. The table and inspector body scroll
  independently; long JSON and original-log blocks have bounded internal scroll.
- Up/Down in the table selects entries without moving the document. The selected
  row remains inside the table's viewport. Tabs support Left/Right/Home/End.
- The first security alert on the loaded page is selected automatically. A page
  containing only telemetry starts with an empty inspector until a row is selected.
- The active detail tab is retained when selecting a different entry.
- Null, empty strings and empty collections are hidden unless Show empty fields
  is enabled. Zero and false remain visible.
- Raw source content is shown as text. Event fields and JSON values are escaped
  before rendering. Source data is never translated or rewritten.

## Frontend filtering with the existing API

Source, type and category use the existing `/api/logs` parameters. Hide telemetry
is enabled initially and requests `kind=alert`; choosing the Telemetry category
disables that switch.

Keyword search and received-time bounds run in the frontend. Search matches all
whitespace-separated terms, case-insensitively, against the event's JSON fields.
Time inputs use the browser's local timezone and filter **SOC received time**.

The adapter scans existing API pages to fill the requested visible page, rather
than searching only its first 100 records. Each request scans up to ten batches
of 500 records. If this budget is reached, a visible notice asks the user to
select Older to continue. Counts labelled source/type/category matches are the
server counts; they are not presented as global keyword-search totals.

Consecutive Zeek telemetry entries are grouped only when their type, agent and
data match after excluding timestamp and connection UID. Distinct metrics,
values and connections remain separate. Groups do not cross visible pages.

The table renders at most 100 entry rows, with extra group headers. JSON children
are created only when opened. A virtualization dependency is not used.

## URL and saved preferences

The query string stores:

`view`, `source`, `type`, `category`, `q`, `from`, `to`, `hideTelemetry`, `limit`,
`before`, `history`, `selected` and `tab`.

Reloading a shared Logs URL restores its filters, cursor page, selection and tab.
Cursor history supports Previous after a reload. A selected Wazuh record outside
the loaded page can also be read through the existing alert-detail endpoint.

The splitter ratio uses `aisoc.logs.ratio` in localStorage. Storage access failures
do not prevent the page from working. The interface uses dark mode only.

Latest pages refresh no more frequently than every 15 seconds while Logs is open.
Older pages remain stable until the user navigates. New filter requests abort
superseded requests to avoid stale responses replacing current results.

## Delivery

Changed files:

- `web/index.html`: complete layout, styles and frontend behavior.
- `docs/logs-workspace.md`: component and behavior reference.

The Wazuh, Zeek, AI and database services require no configuration changes.
