import React from 'react'

export default class ErrorBoundary extends React.Component {
  state = { error: null, info: null }

  componentDidCatch(error, info) {
    this.setState({ error: error.toString(), info: info.componentStack })
    console.error('React error:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{padding:'2rem',maxWidth:'800px',margin:'0 auto'}}>
          <h2 style={{color:'#dc2626',marginBottom:'1rem'}}>Something went wrong</h2>
          <pre style={{background:'#fef2f2',padding:'1rem',borderRadius:'8px',border:'1px solid #fecaca',overflow:'auto',fontSize:'0.85rem'}}>
            {this.state.error}
            {this.state.info}
          </pre>
        </div>
      )
    }
    return this.props.children
  }
}