local webroot = ""

function get_webroot(meta)
    webroot = meta.webroot
end

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
