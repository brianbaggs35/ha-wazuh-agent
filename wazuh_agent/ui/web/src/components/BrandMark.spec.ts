import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import BrandMark from './BrandMark.vue'

describe('BrandMark', () => {
  it('is an image with a text alternative, 32 px by default', () => {
    const svg = mount(BrandMark).find('svg')
    expect(svg.attributes('role')).toBe('img')
    expect(svg.attributes('aria-label')).toContain('Wazuh Agent')
    expect(svg.attributes('width')).toBe('32')
  })

  it('takes a size', () => {
    expect(
      mount(BrandMark, { props: { size: 64 } })
        .find('svg')
        .attributes('height'),
    ).toBe('64')
  })
})
