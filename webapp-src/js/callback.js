
var getParameterByName = function (name, url) {
  if (!url) url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'), results = regex.exec(url);
  if (!results)
    return null;
  if (!results[2])
    return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
};

$(function() {
  var state = getParameterByName("state");
  if (state) {
    try {
      var stateDecoded = JSON.parse(atob(state));
      console.log(stateDecoded);
      $.ajax({
        method: "GET",
        url: "config.json"
      })
      .then((frontEndConfig) => {
        $.ajax({
          method: "GET",
          url: frontEndConfig.GlewlwydUrl + "config/"
        })
        .then((serverConfig) => {
          var data = {
            scheme_name: stateDecoded.module,
            scheme_type: "oauth2",
            username: stateDecoded.username,
            value: {
              action: "callback",
              provider: stateDecoded.provider,
              state: state,
              redirect_to: window.location.href
            }
          }
          $.ajax({
            method: "POST",
            url: stateDecoded.register_url + "/profile/scheme/register/",
            data: JSON.stringify(data),
            contentType: "application/json; charset=utf-8"
          })
          .then(() => {
            var url = stateDecoded.complete_url;
            if (url.indexOf('?') > -1) {
              url += '&';
            } else {
              url += '?';
            }
            url += "scheme_name=" + stateDecoded.module + "&provider=" + stateDecoded.provider;
            window.location.href = url;
          })
          .fail((err) => {
            // TODO
            console.log(err);
          });
        })
        .fail(err => {
          // TODO
          console.log(err);
        });
      })
      .fail((err) => {
        // TODO
        console.log(err);
      });
    } catch(e) {
      // TODO
      console.log(e);
    }
  }
});
