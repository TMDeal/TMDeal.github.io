-- When pandoc converts vimwiki links , they always end up prefixed with file:,
-- even if local was used. This just chops of everything before /images in the
-- src
function Image(el)
    local original = el.src
    local src = original:gsub('file:', "")
    src = src:gsub('%.%./', "")
    el.src = "/" .. src
    return el
end
