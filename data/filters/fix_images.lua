local webroot = ""

function get_webroot(meta)
    webroot = meta.webroot
end

-- When pandoc converts vimwiki links , they always end up prefixed with file:,
-- even if local was used. This just chops of everything before /images in the
-- src and replaces it with the webroot as defined in the files associated
-- metadata
function Image(el)
    local original = el.src
    local src = original:gsub('file:', "")
    src = src:gsub('%.%./', "")
    el.src = webroot .. "/" .. src
    return el
end

return {
    { Meta = get_webroot },
    { Image = Image }
}
