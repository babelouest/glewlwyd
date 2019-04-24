import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';

class Navbar extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      curNav: "profile",
      loggedIn: props.loggedIn,
      schemeList: props.schemeList
    }

    messageDispatcher.subscribe('Navbar', (message) => {
    });
    
    this.navigate = this.navigate.bind(this);
    this.toggleLogin = this.toggleLogin.bind(this);
    this.changeLang = this.changeLang.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({loggedIn: nextProps.loggedIn, schemeList: nextProps.schemeList});
  }
  
  navigate(e, page, type) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "nav", page: page, module: type});
    this.setState({curNav: page});
  }

  toggleLogin() {
    if (this.state.loggedIn) {
      apiManager.glewlwydRequest("/auth/", "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('App', {type: 'loggedIn', loggedIn: false});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
      });
    } else {
      document.location.href = this.state.config.LoginUrl + "?callback_url=" + encodeURI([location.protocol, '//', location.host, location.pathname].join('')) + "&scope=" + encodeURI(this.state.config.profile_scope);
    }
  }

  changeLang(e, lang) {
    i18next.changeLanguage(lang)
    .then(() => {
      this.setState({lang: lang});
      messageDispatcher.sendMessage('App', {type: "lang"});
    });
  }

	render() {
    var langList = [], schemeList = [];
    ["en","fr"].forEach((lang, i) => {
      if (lang === i18next.language) {
        langList.push(<a className="dropdown-item active" href="#" key={i}>{lang}</a>);
      } else {
        langList.push(<a className="dropdown-item" href="#" onClick={(e) => this.changeLang(e, lang)} key={i}>{lang}</a>);
      }
    });
    this.state.schemeList.forEach((scheme, index) => {
      schemeList.push(
        <li className={"nav-item" + (this.state.curNav===scheme.name?" active":"")} key={index}>
          <a className="nav-link" href="#" onClick={(e) => this.navigate(e, scheme.name, scheme.module)}>{scheme.display_name}</a>
        </li>
      );
    });
		return (
      <nav className="navbar navbar-expand-lg navbar-light bg-light">
        <a className="navbar-brand" href="#">Glewlwyd</a>
        <button className="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarSupportedContent">
          <ul className="navbar-nav mr-auto">
            <li className={"nav-item" + (this.state.curNav==="profile"?" active":"")}>
              <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "profile", null)}>{i18next.t("profile.menu-user")}</a>
            </li>
            <li className={"nav-item" + (this.state.curNav==="password"?" active":"")}>
              <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "password", null)}>{i18next.t("profile.menu-password")}</a>
            </li>
            {schemeList}
          </ul>
          <div className="btn-group" role="group">
            <div className="btn-group" role="group">
              <div className="dropdown">
                <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownLang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  <i className="fas fa-globe-africa"></i> {i18next.t("select-lang")}
                </button>
                <div className="dropdown-menu" aria-labelledby="dropdownLang">
                  {langList}
                </div>
              </div>
            </div>
            <button type="button" className="btn btn-secondary" onClick={this.toggleLogin}>
              <i className="fas fa-sign-in-alt btn-icon"></i>{this.state.loggedIn?i18next.t("admin.menu-logout"):i18next.t("admin.menu-login")}
            </button>
          </div>
        </div>
      </nav>
		);
	}
}

export default Navbar;
