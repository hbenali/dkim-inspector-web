// If the URL has domain/selector parameters, log them for debugging (no search form is shown here).
const params = new URLSearchParams(window.location.search);
const domainParam = params.get('domain');
const selectorParam = params.get('selector');
if (domainParam || selectorParam) {
  console.log('404 page accessed with params:', { domainParam, selectorParam });
}
