-- uppercase_selection.lua: an action that edits the document.
--
-- Actions appear in the command palette and menus. They receive an `api`
-- handle for the duration of the call with:
--   api:document_len()        total bytes
--   api:cursor()              cursor offset
--   api:selection()           start, len  (or nil when nothing is selected)
--   api:read(start, len)      bytes as a string
--   api:replace(start, len, s) replace a range (undoable in the viewer)
--   api:select(start, len)    set the selection
--   api:status(text)          show a message in the status bar
-- The handle stops working when the action returns.

theviewer.register_action{
  id = "uppercase-selection",
  title = "Uppercase the selected ASCII text",
  run = function(api)
    local start, len = api:selection()
    if not start then
      api:status("Select some text first")
      return
    end
    local text = api:read(start, len)
    api:replace(start, len, text:upper())
    api:select(start, len)
    api:status(string.format("Uppercased %d bytes", len))
  end,
}
